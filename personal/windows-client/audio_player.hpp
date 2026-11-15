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
// Device changes: an IMMNotificationClient wakes the render thread as soon
// as Windows switches the default output or a device changes state (the 2 s
// default-device poll stays as a backup). While no device is open the jitter
// buffer is marked idle, so the gap is dropped at the target instead of
// piling up, and the new device starts from the live edge (see "Output gaps"
// in audio_jitter.hpp). A device that cannot be opened is retried after
// 0.5, 1, 2, 4, then every 5 s, or at once when Windows reports a change.
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
    uint64_t deviceReopens = 0;      // an open device had to be closed and opened again
    uint64_t deviceNotifications = 0;  // default-output / device-state changes reported by Windows
    std::string lastReopenReason;    // "" until the first reopen
    uint32_t deviceBufferFrames = 0;
    uint32_t devicePaddingFrames = 0;  // queued in the device at the last fill
    uint32_t deviceLatencyFrames = 0;  // IAudioClient::GetStreamLatency
    bool deviceOk = false;
    bool deviceNotify = false;       // change notifications registered
    bool muted = false;

    // Audio received but not yet heard: jitter buffer + device queue + the
    // device's own stream latency. An estimate (no DAC or speaker delay).
    double outputLatencyMs() const {
        return jb.bufferedMs + double(devicePaddingFrames + deviceLatencyFrames) * 1000.0 / kSampleRate;
    }
};

// Wakes the render thread when Windows changes the default output, adds or
// removes a device, or changes a device's state. Called on a system thread,
// so it only counts and sets its own event; it owns that event so the handle
// stays valid for as long as Windows holds a reference.
class DeviceNotifier final : public IMMNotificationClient {
public:
    DeviceNotifier() : event_(CreateEventW(nullptr, FALSE, FALSE, nullptr)) {}
    HANDLE event() const { return event_; }
    uint64_t count() const { return count_; }

    ULONG STDMETHODCALLTYPE AddRef() override { return ULONG(InterlockedIncrement(&ref_)); }
    ULONG STDMETHODCALLTYPE Release() override {
        const LONG r = InterlockedDecrement(&ref_);
        if (r == 0) delete this;
        return ULONG(r);
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(IMMNotificationClient)) {
            *out = static_cast<IMMNotificationClient*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE OnDefaultDeviceChanged(EDataFlow flow, ERole role, LPCWSTR) override {
        if (flow == eRender && role == eConsole) signal();
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE OnDeviceStateChanged(LPCWSTR, DWORD) override { signal(); return S_OK; }
    HRESULT STDMETHODCALLTYPE OnDeviceAdded(LPCWSTR) override { signal(); return S_OK; }
    HRESULT STDMETHODCALLTYPE OnDeviceRemoved(LPCWSTR) override { signal(); return S_OK; }
    HRESULT STDMETHODCALLTYPE OnPropertyValueChanged(LPCWSTR, const PROPERTYKEY) override { return S_OK; }

private:
    ~DeviceNotifier() { if (event_) CloseHandle(event_); }
    void signal() {
        ++count_;
        if (event_) SetEvent(event_);
    }
    LONG ref_ = 1;
    HANDLE event_ = nullptr;
    std::atomic<uint64_t> count_{0};
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
        {
            // No device yet: anything that arrives before it opens is a gap.
            std::lock_guard<std::mutex> lk(mu_);
            jb_.setOutputActive(false);
        }
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
        {
            std::lock_guard<std::mutex> lk(reasonMu_);
            s.lastReopenReason = lastReopenReason_;
        }
        s.deviceOpens = deviceOpens_;
        s.deviceErrors = deviceErrors_;
        s.deviceReopens = deviceReopens_;
        s.deviceNotifications = deviceNotifications_;
        s.deviceBufferFrames = deviceBufferFrames_;
        s.devicePaddingFrames = devicePaddingFrames_;
        s.deviceLatencyFrames = deviceLatencyFrames_;
        s.deviceOk = deviceOk_;
        s.deviceNotify = deviceNotify_;
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
        // Change notifications live on their own enumerator for the whole
        // session; without them the 2 s poll still catches default changes.
        Microsoft::WRL::ComPtr<IMMDeviceEnumerator> notifyEnum;
        DeviceNotifier* notifier = new DeviceNotifier();
        if (notifier->event() &&
            SUCCEEDED(CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, IID_PPV_ARGS(&notifyEnum))) &&
            SUCCEEDED(notifyEnum->RegisterEndpointNotificationCallback(notifier))) {
            deviceNotify_ = true;
        } else {
            notifyEnum.Reset();
        }
        const HANDLE changeEvent = deviceNotify_ ? notifier->event() : nullptr;
        log_(std::string("audio: device notifications=") + (deviceNotify_ ? "on" : "off (polling every 2 s)"));
        DWORD retryMs = kRetryFirstMs;
        uint64_t openFailures = 0;
        std::string lastFailure;
        while (!stop_ && deviceEvent) {
            std::string why;
            if (!openDevice(deviceEvent, why)) {
                ++deviceErrors_;
                ++openFailures;
                // Log the first failure and any change of reason, not every retry.
                if (why != lastFailure)
                    log_("audio: device open failed: " + why + "; retrying with backoff (0.5 s .. 5 s)");
                lastFailure = why;
                closeDevice();
                waitStopOrChange(changeEvent, retryMs, notifier);
                retryMs = retryMs * 2 > kRetryMaxMs ? kRetryMaxMs : retryMs * 2;
                continue;
            }
            if (openFailures)
                log_("audio: device open recovered after " + std::to_string(openFailures) + " failed attempts");
            openFailures = 0;
            lastFailure.clear();
            retryMs = kRetryFirstMs;
            ++deviceOpens_;
            deviceOk_ = true;
            {
                std::lock_guard<std::mutex> lk(mu_);
                jb_.setOutputActive(true);
            }
            log_("audio: device open buffer_frames=" + std::to_string(deviceBufferFrames_.load()) +
                 " stream_latency_frames=" + std::to_string(deviceLatencyFrames_.load()) +
                 " mmcss=" + (mmcss ? "yes" : "no"));
            why = runDevice(deviceEvent, changeEvent, notifier);
            {
                std::lock_guard<std::mutex> lk(mu_);
                jb_.setOutputActive(false);
            }
            deviceOk_ = false;
            closeDevice();
            if (!stop_) {
                ++deviceReopens_;
                {
                    std::lock_guard<std::mutex> lk(reasonMu_);
                    lastReopenReason_ = why;
                }
                log_("audio: device reopen: " + why);
                WaitForSingleObject(stopEvent_, 100);
            }
        }
        if (notifyEnum) notifyEnum->UnregisterEndpointNotificationCallback(notifier);
        notifyEnum.Reset();
        notifier->Release();
        if (deviceEvent) CloseHandle(deviceEvent);
        if (mmcss) AvRevertMmThreadCharacteristics(mmcss);
        if (SUCCEEDED(co)) CoUninitialize();
    }

    static constexpr DWORD kRetryFirstMs = 500;
    static constexpr DWORD kRetryMaxMs = 5000;

    // Sleeps up to `ms`, waking early on stop or a device change.
    void waitStopOrChange(HANDLE changeEvent, DWORD ms, const DeviceNotifier* notifier) {
        HANDLE waits[2] = {stopEvent_, changeEvent};
        WaitForMultipleObjects(changeEvent ? 2 : 1, waits, FALSE, ms);
        deviceNotifications_ = notifier->count();
    }

    // HRESULT as hex, with a name for the codes a device change produces.
    static std::string hex(HRESULT hr) {
        char b[16];
        std::snprintf(b, sizeof(b), "0x%08lx", static_cast<unsigned long>(hr));
        const char* name = nullptr;
        switch (static_cast<unsigned long>(hr)) {
        case 0x88890004ul: name = "device invalidated"; break;     // AUDCLNT_E_DEVICE_INVALIDATED
        case 0x8889000Aul: name = "device in use"; break;          // AUDCLNT_E_DEVICE_IN_USE
        case 0x88890010ul: name = "audio service stopped"; break;  // AUDCLNT_E_SERVICE_NOT_RUNNING
        case 0x88890026ul: name = "resources invalidated"; break;  // AUDCLNT_E_RESOURCES_INVALIDATED
        case 0x80070490ul: name = "not found"; break;              // E_NOTFOUND
        default: break;
        }
        return name ? std::string(b) + " (" + name + ")" : std::string(b);
    }

    // True while the device we play to is still present and enabled.
    bool deviceStillActive() {
        if (!enumerator_ || deviceId_.empty()) return true;
        Microsoft::WRL::ComPtr<IMMDevice> d;
        if (FAILED(enumerator_->GetDevice(deviceId_.c_str(), &d))) return false;
        DWORD state = 0;
        if (FAILED(d->GetState(&state))) return true;  // unknown: let the next call fail if it is gone
        return state == DEVICE_STATE_ACTIVE;
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
        REFERENCE_TIME latency = 0;  // 100 ns units
        deviceLatencyFrames_ = SUCCEEDED(client_->GetStreamLatency(&latency)) && latency > 0
            ? uint32_t(latency * kSampleRate / 10000000) : 0;
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
    std::string runDevice(HANDLE deviceEvent, HANDLE changeEvent, const DeviceNotifier* notifier) {
        HANDLE waits[3] = {deviceEvent, stopEvent_, changeEvent};
        auto lastDefaultCheck = std::chrono::steady_clock::now();
        while (!stop_) {
            const DWORD w = WaitForMultipleObjects(changeEvent ? 3 : 2, waits, FALSE, 200);
            if (w == WAIT_OBJECT_0 + 1) return "";
            if (w == WAIT_OBJECT_0 + 2) {
                // Windows reported a change; only some of them concern us.
                deviceNotifications_ = notifier->count();
                const std::wstring id = defaultDeviceId();
                if (!id.empty() && id != deviceId_) return "default output changed";
                if (!deviceStillActive()) return "output device removed or disabled";
            }
            const auto now = std::chrono::steady_clock::now();
            if (now - lastDefaultCheck >= std::chrono::seconds(2)) {
                // Backup for a missed notification: headphones plugged in /
                // default output changed on the PC.
                lastDefaultCheck = now;
                const std::wstring id = defaultDeviceId();
                if (!id.empty() && id != deviceId_) return "default output changed (poll)";
            }
            UINT32 padding = 0;
            HRESULT hr = client_->GetCurrentPadding(&padding);
            if (FAILED(hr)) { ++deviceErrors_; return "padding " + hex(hr); }
            devicePaddingFrames_ = padding;
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
        devicePaddingFrames_ = 0;
        deviceLatencyFrames_ = 0;
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
    std::atomic<uint64_t> deviceReopens_{0};
    std::atomic<uint64_t> deviceNotifications_{0};
    std::atomic<uint32_t> deviceBufferFrames_{0};
    std::atomic<uint32_t> devicePaddingFrames_{0};
    std::atomic<uint32_t> deviceLatencyFrames_{0};
    std::atomic<bool> deviceOk_{false};
    std::atomic<bool> deviceNotify_{false};
    std::mutex reasonMu_;
    std::string lastReopenReason_;
};

}  // namespace jl::audio
