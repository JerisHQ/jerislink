#pragma once
// Mac audio playback for the viewer: 48 kHz stereo in MRA1, Opus (v2, A2)
// or s16 PCM (v1, from an A1 host).
//
// Two threads, neither touches the UI or the input loop:
//   net thread    - its own UDP socket on bindIp:0, recvfrom with a peer IP
//                   check, pushes MRA1 packets into the jitter buffer.
//                   Opus is decoded later, on the render thread, in order.
//   render thread - MMCSS "Pro Audio", WASAPI shared mode, event driven, on
//                   the default render device. Each event fills what the
//                   device has room for from the jitter buffer. Reopens on
//                   device loss or when the default device changes.
// The main loop only reads stats(), flips mute, and sends the MRM1 0x45
// request naming port() over its existing MRM1 socket.
//
// Mute is local: the packets keep flowing and the buffer keeps draining (so
// unmuting does not play stale audio); only the device gets silence.

#include "audio_jitter.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <avrt.h>
#include <wrl/client.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

#pragma comment(lib, "avrt.lib")

namespace jl::audio {

struct PlayerStats {
    JitterStats jb;
    uint64_t rxBadPeer = 0;
    uint64_t rxMalformed = 0;
    uint64_t deviceOpens = 0;
    uint64_t deviceErrors = 0;
    uint32_t deviceBufferFrames = 0;
    bool deviceOk = false;
    bool muted = false;
};

class AudioPlayer {
public:
    using LogFn = std::function<void(const std::string&)>;

    explicit AudioPlayer(LogFn log) : log_(std::move(log)) {}
    ~AudioPlayer() { stop(); }
    AudioPlayer(const AudioPlayer&) = delete;
    AudioPlayer& operator=(const AudioPlayer&) = delete;

    // Opens the socket and starts both threads. The device is opened on the
    // render thread; a missing device is retried there, not reported here.
    bool start(const std::string& bindIp, const std::string& peerIp, std::string& err) {
        if (running_) return true;
        if (inet_pton(AF_INET, peerIp.c_str(), &peer_) != 1) { err = "audio peer IP invalid"; return false; }
        s_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s_ == INVALID_SOCKET) { err = "audio UDP socket failed"; return false; }
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        int len = sizeof(local);
        if (inet_pton(AF_INET, bindIp.c_str(), &local.sin_addr) != 1 ||
            bind(s_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0 ||
            getsockname(s_, reinterpret_cast<sockaddr*>(&local), &len) != 0) {
            closesocket(s_); s_ = INVALID_SOCKET;
            err = "audio UDP bind failed";
            return false;
        }
        port_ = ntohs(local.sin_port);
        int rcvbuf = 256 * 1024;
        setsockopt(s_, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
        DWORD timeoutMs = 200;  // lets the net thread notice stop()
        setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
        stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stopEvent_) {
            closesocket(s_); s_ = INVALID_SOCKET;
            err = "audio stop event failed";
            return false;
        }
        stop_ = false;
        running_ = true;
        net_ = std::thread([this] { netLoop(); });
        render_ = std::thread([this] { renderLoop(); });
        return true;
    }

    void stop() {
        if (!running_) return;
        stop_ = true;
        SetEvent(stopEvent_);
        if (net_.joinable()) net_.join();
        if (render_.joinable()) render_.join();
        closesocket(s_); s_ = INVALID_SOCKET;
        CloseHandle(stopEvent_); stopEvent_ = nullptr;
        running_ = false;
    }

    uint16_t port() const { return port_; }
    bool running() const { return running_; }
    void setMuted(bool m) { muted_ = m; }
    bool muted() const { return muted_; }

    PlayerStats stats() {
        PlayerStats s;
        {
            std::lock_guard<std::mutex> lk(mu_);
            s.jb = jb_.stats();
        }
        s.rxBadPeer = rxBadPeer_;
        s.rxMalformed = rxMalformed_;
        s.deviceOpens = deviceOpens_;
        s.deviceErrors = deviceErrors_;
        s.deviceBufferFrames = deviceBufferFrames_;
        s.deviceOk = deviceOk_;
        s.muted = muted_;
        return s;
    }

private:
    static uint64_t nowUs() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    void netLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
        uint8_t buf[kHeaderBytes + kMaxFramesPerPacket * kChannels * 2 + 16];
        while (!stop_) {
            sockaddr_in from{};
            int flen = sizeof(from);
            const int n = recvfrom(s_, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                   reinterpret_cast<sockaddr*>(&from), &flen);
            if (n == SOCKET_ERROR) continue;  // timeout (checks stop_) or ICMP noise
            if (from.sin_addr.s_addr != peer_.s_addr) { ++rxBadPeer_; continue; }
            Mra1Packet p;
            if (!parseMra1(buf, size_t(n), p)) { ++rxMalformed_; continue; }
            const uint64_t at = nowUs();
            std::lock_guard<std::mutex> lk(mu_);
            jb_.push(p, at);
        }
    }

    void renderLoop() {
        const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        DWORD taskIndex = 0;
        HANDLE mmcss = AvSetMmThreadCharacteristicsW(L"Pro Audio", &taskIndex);
        HANDLE deviceEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        bool loggedOpenFailure = false;
        while (!stop_ && deviceEvent) {
            std::string why;
            if (!openDevice(deviceEvent, why)) {
                ++deviceErrors_;
                if (!loggedOpenFailure) log_("audio: device open failed: " + why + "; retrying every 1 s");
                loggedOpenFailure = true;
                closeDevice();
                WaitForSingleObject(stopEvent_, 1000);
                continue;
            }
            loggedOpenFailure = false;
            ++deviceOpens_;
            deviceOk_ = true;
            log_("audio: device open buffer_frames=" + std::to_string(deviceBufferFrames_.load()) +
                 " mmcss=" + (mmcss ? "yes" : "no"));
            why = runDevice(deviceEvent);
            deviceOk_ = false;
            closeDevice();
            if (!stop_) {
                log_("audio: device reopen: " + why);
                WaitForSingleObject(stopEvent_, 100);
            }
        }
        if (deviceEvent) CloseHandle(deviceEvent);
        if (mmcss) AvRevertMmThreadCharacteristics(mmcss);
        if (SUCCEEDED(co)) CoUninitialize();
    }

    static std::string hex(HRESULT hr) {
        char b[16];
        std::snprintf(b, sizeof(b), "0x%08lx", static_cast<unsigned long>(hr));
        return b;
    }

    std::wstring defaultDeviceId() {
        Microsoft::WRL::ComPtr<IMMDevice> d;
        if (!enumerator_ || FAILED(enumerator_->GetDefaultAudioEndpoint(eRender, eConsole, &d))) return {};
        LPWSTR id = nullptr;
        if (FAILED(d->GetId(&id)) || !id) return {};
        std::wstring s(id);
        CoTaskMemFree(id);
        return s;
    }

    bool openDevice(HANDLE deviceEvent, std::string& why) {
        HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL,
                                      IID_PPV_ARGS(&enumerator_));
        if (FAILED(hr)) { why = "enumerator " + hex(hr); return false; }
        Microsoft::WRL::ComPtr<IMMDevice> device;
        hr = enumerator_->GetDefaultAudioEndpoint(eRender, eConsole, &device);
        if (FAILED(hr)) { why = "no default output " + hex(hr); return false; }
        LPWSTR id = nullptr;
        if (SUCCEEDED(device->GetId(&id)) && id) { deviceId_ = id; CoTaskMemFree(id); }
        hr = device->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr,
                              reinterpret_cast<void**>(client_.ReleaseAndGetAddressOf()));
        if (FAILED(hr)) { why = "activate " + hex(hr); return false; }
        WAVEFORMATEX wf{};
        wf.wFormatTag = WAVE_FORMAT_PCM;
        wf.nChannels = kChannels;
        wf.nSamplesPerSec = kSampleRate;
        wf.wBitsPerSample = 16;
        wf.nBlockAlign = kChannels * 2;
        wf.nAvgBytesPerSec = kSampleRate * wf.nBlockAlign;
        // 20 ms device buffer; the engine converts to the mix format if needed.
        hr = client_->Initialize(AUDCLNT_SHAREMODE_SHARED,
                                 AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM |
                                     AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY,
                                 200000, 0, &wf, nullptr);
        if (FAILED(hr)) { why = "initialize " + hex(hr); return false; }
        if (FAILED(hr = client_->SetEventHandle(deviceEvent))) { why = "event " + hex(hr); return false; }
        UINT32 frames = 0;
        if (FAILED(hr = client_->GetBufferSize(&frames))) { why = "buffer size " + hex(hr); return false; }
        deviceBufferFrames_ = frames;
        hr = client_->GetService(IID_PPV_ARGS(&render_client_));
        if (FAILED(hr)) { why = "render client " + hex(hr); return false; }
        // Start with one silent buffer so the first event has room to fill.
        BYTE* data = nullptr;
        if (SUCCEEDED(render_client_->GetBuffer(frames, &data)))
            render_client_->ReleaseBuffer(frames, AUDCLNT_BUFFERFLAGS_SILENT);
        if (FAILED(hr = client_->Start())) { why = "start " + hex(hr); return false; }
        return true;
    }

    // Returns why the device has to be reopened ("" on stop).
    std::string runDevice(HANDLE deviceEvent) {
        HANDLE waits[2] = {deviceEvent, stopEvent_};
        auto lastDefaultCheck = std::chrono::steady_clock::now();
        while (!stop_) {
            const DWORD w = WaitForMultipleObjects(2, waits, FALSE, 200);
            if (w == WAIT_OBJECT_0 + 1) return "";
            const auto now = std::chrono::steady_clock::now();
            if (now - lastDefaultCheck >= std::chrono::seconds(2)) {
                // Headphones plugged in / default output changed on the PC.
                lastDefaultCheck = now;
                const std::wstring id = defaultDeviceId();
                if (!id.empty() && id != deviceId_) return "default output changed";
            }
            UINT32 padding = 0;
            HRESULT hr = client_->GetCurrentPadding(&padding);
            if (FAILED(hr)) { ++deviceErrors_; return "padding " + hex(hr); }
            const UINT32 room = deviceBufferFrames_ - std::min<UINT32>(padding, deviceBufferFrames_);
            if (room == 0) continue;
            BYTE* data = nullptr;
            hr = render_client_->GetBuffer(room, &data);
            if (FAILED(hr)) { ++deviceErrors_; return "get buffer " + hex(hr); }
            {
                std::lock_guard<std::mutex> lk(mu_);
                jb_.pull(reinterpret_cast<int16_t*>(data), room);
            }
            hr = render_client_->ReleaseBuffer(room, muted_ ? AUDCLNT_BUFFERFLAGS_SILENT : 0);
            if (FAILED(hr)) { ++deviceErrors_; return "release buffer " + hex(hr); }
        }
        return "";
    }

    void closeDevice() {
        if (client_) client_->Stop();
        render_client_.Reset();
        client_.Reset();
        enumerator_.Reset();
        deviceBufferFrames_ = 0;
    }

    LogFn log_;
    SOCKET s_ = INVALID_SOCKET;
    in_addr peer_{};
    uint16_t port_ = 0;
    HANDLE stopEvent_ = nullptr;
    std::thread net_;
    std::thread render_;
    bool running_ = false;
    std::atomic<bool> stop_{false};
    std::atomic<bool> muted_{false};

    std::mutex mu_;
    JitterBuffer jb_;

    // Render thread only (COM objects live in its apartment).
    Microsoft::WRL::ComPtr<IMMDeviceEnumerator> enumerator_;
    Microsoft::WRL::ComPtr<IAudioClient> client_;
    Microsoft::WRL::ComPtr<IAudioRenderClient> render_client_;
    std::wstring deviceId_;

    std::atomic<uint64_t> rxBadPeer_{0};
    std::atomic<uint64_t> rxMalformed_{0};
    std::atomic<uint64_t> deviceOpens_{0};
    std::atomic<uint64_t> deviceErrors_{0};
    std::atomic<uint32_t> deviceBufferFrames_{0};
    std::atomic<bool> deviceOk_{false};
};

}  // namespace jl::audio
