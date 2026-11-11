#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <wmcodecdsp.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

using Microsoft::WRL::ComPtr;

static std::string tempProbePath(const char* filename) {
    char buf[MAX_PATH + 2]{};
    DWORD n = GetTempPathA(static_cast<DWORD>(sizeof(buf)), buf);
    if (n == 0 || n >= sizeof(buf)) return filename;
    return std::string(buf) + filename;
}
static const std::string kNativeProbeLog = tempProbePath("jerislink-native.log");
static const std::string kDxgiProbeLog = tempProbePath("jerislink-dxgi.log");

static void trace(const char* msg) {
    std::ofstream f(kNativeProbeLog, std::ios::app);
    f << msg << "\n";
    f.flush();
}

static void check(HRESULT hr, const char* what) {
    if (FAILED(hr)) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "%s failed: 0x%08lx", what, static_cast<unsigned long>(hr));
        throw std::runtime_error(buf);
    }
}

struct Options {
    std::string bindIp;
    std::string sourceIp;
    uint16_t port = 38401;
    int idleTimeoutMs = 60000;
    UINT32 width = 1760;
    UINT32 height = 990;
    UINT32 fps = 60;
};

static std::string envValue(const char* name) {
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || value == nullptr) return {};
    std::string out(value);
    free(value);
    return out;
}

static std::optional<Options> parse_args(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        if (i + 1 >= argc) return std::nullopt;
        std::string k = argv[i], v = argv[++i];
        if (k == "--bind-ip") o.bindIp = v;
        else if (k == "--source-ip") o.sourceIp = v;
        else if (k == "--port") o.port = static_cast<uint16_t>(std::stoi(v));
        else if (k == "--idle-timeout-ms") o.idleTimeoutMs = std::stoi(v);
        else if (k == "--width") o.width = static_cast<UINT32>(std::stoul(v));
        else if (k == "--height") o.height = static_cast<UINT32>(std::stoul(v));
        else if (k == "--fps") o.fps = static_cast<UINT32>(std::stoul(v));
        else return std::nullopt;
    }
    if (o.bindIp.empty()) return std::nullopt;
    if (o.sourceIp.empty()) o.sourceIp = envValue("JERISLINK_SOURCE_IP");
    if (o.sourceIp.empty()) return std::nullopt;
    return o;
}

static uint16_t be16(const uint8_t* p) {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | uint16_t(p[1]));
}
static uint64_t be64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | uint64_t(p[i]);
    return v;
}

struct FrameAssembly {
    uint16_t packetCount = 0;
    bool keyFrame = false;
    std::vector<std::vector<uint8_t>> parts;
    std::vector<bool> present;
    size_t received = 0;

    explicit FrameAssembly(uint16_t count = 0)
        : packetCount(count), parts(count), present(count, false) {}

    void add(uint16_t index, const uint8_t* data, size_t size, bool key) {
        if (index >= packetCount || present[index]) return;
        parts[index].assign(data, data + size);
        present[index] = true;
        keyFrame = keyFrame || key;
        ++received;
    }
    bool complete() const { return packetCount && received == packetCount; }
    std::vector<uint8_t> join() const {
        size_t total = 0;
        for (const auto& p : parts) total += p.size();
        std::vector<uint8_t> out;
        out.reserve(total);
        for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
        return out;
    }
};

class H264Decoder {
public:
    H264Decoder(UINT32 width, UINT32 height, UINT32 fps) : width_(width), height_(height), fps_(fps) {
        createD3D();
        createDecoder();
    }

    ~H264Decoder() {
        if (decoder_ && !finished_) {
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }

    bool hardwarePath() const { return d3dAware_; }
    uint64_t decodedFrames() const { return decodedFrames_; }
    uint64_t streamChanges() const { return streamChanges_; }
    uint64_t inputBackpressure() const { return inputBackpressure_; }
    uint64_t dxgiFrames() const { return dxgiFrames_; }

    void submit(uint64_t frameId, const std::vector<uint8_t>& annexB, bool discontinuity) {
        ComPtr<IMFSample> sample;
        ComPtr<IMFMediaBuffer> buffer;
        check(MFCreateSample(&sample), "MFCreateSample");
        check(MFCreateMemoryBuffer(static_cast<DWORD>(annexB.size()), &buffer), "MFCreateMemoryBuffer");
        BYTE* dst = nullptr;
        DWORD maxLen = 0, curLen = 0;
        check(buffer->Lock(&dst, &maxLen, &curLen), "buffer Lock");
        std::memcpy(dst, annexB.data(), annexB.size());
        buffer->Unlock();
        check(buffer->SetCurrentLength(static_cast<DWORD>(annexB.size())), "SetCurrentLength");
        check(sample->AddBuffer(buffer.Get()), "AddBuffer");

        const LONGLONG t = static_cast<LONGLONG>((frameId - 1) * 10000000ULL / fps_);
        const LONGLONG d = static_cast<LONGLONG>(10000000ULL / fps_);
        sample->SetSampleTime(t);
        sample->SetSampleDuration(d);
        if (discontinuity) sample->SetUINT32(MFSampleExtension_Discontinuity, TRUE);

        HRESULT hr = decoder_->ProcessInput(0, sample.Get(), 0);
        if (hr == MF_E_NOTACCEPTING) {
            ++inputBackpressure_;
            drain();
            hr = decoder_->ProcessInput(0, sample.Get(), 0);
        }
        check(hr, "decoder ProcessInput");
        drain();
    }

    void drain() {
        for (;;) {
            MFT_OUTPUT_STREAM_INFO osi{};
            check(decoder_->GetOutputStreamInfo(0, &osi), "GetOutputStreamInfo");

            ComPtr<IMFSample> clientSample;
            ComPtr<IMFMediaBuffer> clientBuffer;
            MFT_OUTPUT_DATA_BUFFER odb{};
            if ((osi.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) == 0 &&
                (osi.dwFlags & MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES) == 0) {
                check(MFCreateSample(&clientSample), "MFCreateSample output");
                const DWORD cb = std::max<DWORD>(osi.cbSize, width_ * height_ * 3 / 2);
                check(MFCreateMemoryBuffer(cb, &clientBuffer), "MFCreateMemoryBuffer output");
                check(clientSample->AddBuffer(clientBuffer.Get()), "AddBuffer output");
                odb.pSample = clientSample.Get();
            }

            DWORD status = 0;
            HRESULT hr = decoder_->ProcessOutput(0, 1, &odb, &status);
            if (odb.pEvents) odb.pEvents->Release();

            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) return;
            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                ++streamChanges_;
                setOutputType();
                continue;
            }
            check(hr, "decoder ProcessOutput");
            if (odb.pSample) { inspectOutputSample(odb.pSample); ++decodedFrames_; }
            if (odb.pSample && odb.pSample != clientSample.Get()) odb.pSample->Release();
        }
    }

    void inspectOutputSample(IMFSample* sample) {
        if (!sample) return;
        ComPtr<IMFMediaBuffer> mb;
        if (FAILED(sample->GetBufferByIndex(0, &mb))) return;
        ComPtr<IMFDXGIBuffer> dxgiBuf;
        if (FAILED(mb.As(&dxgiBuf))) return;
        ComPtr<ID3D11Texture2D> tex;
        if (FAILED(dxgiBuf->GetResource(IID_PPV_ARGS(&tex)))) return;
        UINT subresource = 0;
        dxgiBuf->GetSubresourceIndex(&subresource);
        ++dxgiFrames_;
        if (!loggedDxgi_) {
            D3D11_TEXTURE2D_DESC d{};
            tex->GetDesc(&d);
            std::ofstream f(kDxgiProbeLog, std::ios::trunc);
            f << "DXGI_TEXTURE width=" << d.Width
              << " height=" << d.Height
              << " format=" << static_cast<unsigned>(d.Format)
              << " array=" << d.ArraySize
              << " bind=0x" << std::hex << d.BindFlags << std::dec
              << " subresource=" << subresource << "\n";
            loggedDxgi_ = true;
        }
    }

    void finish() {
        if (finished_) return;
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0), "NOTIFY_END_OF_STREAM");
        check(decoder_->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0), "COMMAND_DRAIN");
        drain();
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0), "NOTIFY_END_STREAMING");
        finished_ = true;
    }

private:
    void createD3D() {
        trace("createD3D.begin");
        UINT flags = D3D11_CREATE_DEVICE_VIDEO_SUPPORT | D3D11_CREATE_DEVICE_BGRA_SUPPORT;
        D3D_FEATURE_LEVEL fl{};
        check(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags, nullptr, 0,
                                D3D11_SDK_VERSION, &d3d_, &fl, &ctx_), "D3D11CreateDevice");
        trace("createD3D.device_ok");
        check(MFCreateDXGIDeviceManager(&resetToken_, &dxgiManager_), "MFCreateDXGIDeviceManager");
        check(dxgiManager_->ResetDevice(d3d_.Get(), resetToken_), "DXGI manager ResetDevice");
        trace("createD3D.end");
    }

    void createDecoder() {
        trace("createDecoder.begin");
        check(CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                               IID_PPV_ARGS(&decoder_)), "CoCreate H264 decoder");
        trace("createDecoder.cocreate_ok");

        ComPtr<IMFAttributes> attrs;
        if (SUCCEEDED(decoder_->GetAttributes(&attrs))) {
            UINT32 aware = FALSE;
            if (SUCCEEDED(attrs->GetUINT32(MF_SA_D3D11_AWARE, &aware)) && aware) {
                check(decoder_->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                      reinterpret_cast<ULONG_PTR>(dxgiManager_.Get())), "SET_D3D_MANAGER");
                d3dAware_ = true;
            }
        }

        ComPtr<IMFMediaType> input;
        check(MFCreateMediaType(&input), "MFCreateMediaType input");
        check(input->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "input major type");
        check(input->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264_ES), "input subtype");
        check(MFSetAttributeSize(input.Get(), MF_MT_FRAME_SIZE, width_, height_), "input frame size");
        check(MFSetAttributeRatio(input.Get(), MF_MT_FRAME_RATE, fps_, 1), "input frame rate");
        check(input->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive), "input interlace");
        check(decoder_->SetInputType(0, input.Get(), 0), "SetInputType");
        trace("createDecoder.input_type_ok");

        setOutputType();
        decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
        decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        trace("createDecoder.end");
    }

    void setOutputType() {
        ComPtr<IMFMediaType> chosen;
        for (DWORD i = 0;; ++i) {
            ComPtr<IMFMediaType> t;
            HRESULT hr = decoder_->GetOutputAvailableType(0, i, &t);
            if (hr == MF_E_NO_MORE_TYPES) break;
            check(hr, "GetOutputAvailableType");
            GUID subtype{};
            if (SUCCEEDED(t->GetGUID(MF_MT_SUBTYPE, &subtype)) && subtype == MFVideoFormat_NV12) {
                chosen = t;
                break;
            }
        }
        if (!chosen) throw std::runtime_error("decoder did not offer NV12 output");
        check(decoder_->SetOutputType(0, chosen.Get(), 0), "SetOutputType NV12");
    }

    UINT32 width_, height_, fps_;
    ComPtr<ID3D11Device> d3d_;
    ComPtr<ID3D11DeviceContext> ctx_;
    ComPtr<IMFDXGIDeviceManager> dxgiManager_;
    UINT resetToken_ = 0;
    ComPtr<IMFTransform> decoder_;
    bool d3dAware_ = false;
    bool finished_ = false;
    uint64_t decodedFrames_ = 0;
    uint64_t streamChanges_ = 0;
    uint64_t inputBackpressure_ = 0;
    uint64_t dxgiFrames_ = 0;
    bool loggedDxgi_ = false;
};

int main(int argc, char** argv) {
    auto parsed = parse_args(argc, argv);
    if (!parsed) {
        std::cerr << "Usage: JerislinkDecodeProbe --bind-ip <local-tailscale-ip> --source-ip <mac-host-ip> [--port 38401] [--width 1760] [--height 990] [--fps 60] [--idle-timeout-ms 60000]\n";
        return 2;
    }
    const auto o = *parsed;

    std::remove(kNativeProbeLog.c_str());
    std::remove(kDxgiProbeLog.c_str());
    trace("main.begin");
    try {
        trace("before.CoInitializeEx");
        check(CoInitializeEx(nullptr, COINIT_MULTITHREADED), "CoInitializeEx");
        trace("after.CoInitializeEx");
        trace("before.MFStartup");
        check(MFStartup(MF_VERSION, MFSTARTUP_FULL), "MFStartup");
        trace("after.MFStartup");

        WSADATA wsa{};
        trace("before.WSAStartup");
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) throw std::runtime_error("WSAStartup failed");
        trace("after.WSAStartup");

        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) throw std::runtime_error("socket failed");
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
        DWORD timeout = static_cast<DWORD>(o.idleTimeoutMs);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(o.port);
        if (inet_pton(AF_INET, o.bindIp.c_str(), &local.sin_addr) != 1 ||
            bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            throw std::runtime_error("bind failed");
        }
        in_addr allowed{};
        if (inet_pton(AF_INET, o.sourceIp.c_str(), &allowed) != 1) throw std::runtime_error("bad source IP");

        trace("before.H264Decoder");
        auto decoder = std::make_unique<H264Decoder>(o.width, o.height, o.fps);
        trace("after.H264Decoder");
        std::cout << "Jerislink 0.0.4 decoder probe\n"
                  << "Bind: " << o.bindIp << ':' << o.port << " source=" << o.sourceIp << "\n"
                  << "Media Foundation D3D11-aware path: " << (decoder->hardwarePath() ? "YES" : "NO") << "\n"
                  << "Waiting for stream...\n";

        std::unordered_map<uint64_t, FrameAssembly> assembling;
        uint64_t packets = 0, complete = 0, incompleteDropped = 0, bad = 0, rejected = 0;
        uint64_t newestFrameSeen = 0;
        uint64_t lastSubmitted = 0;
        std::vector<uint8_t> buf(2048);

        for (;;) {
            sockaddr_in peer{}; int plen = sizeof(peer);
            int n = recvfrom(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&peer), &plen);
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) break;
                throw std::runtime_error("recvfrom failed");
            }
            if (peer.sin_addr.s_addr != allowed.s_addr) { ++rejected; continue; }
            ++packets;
            if (n < 20 || std::memcmp(buf.data(), "MR02", 4) || buf[4] != 1) { ++bad; continue; }

            uint8_t flags = buf[5];
            uint64_t fid = be64(buf.data()+6);
            uint16_t idx = be16(buf.data()+14), cnt = be16(buf.data()+16), len = be16(buf.data()+18);
            if (!cnt || idx >= cnt || len != static_cast<uint16_t>(n-20)) { ++bad; continue; }

            newestFrameSeen = std::max(newestFrameSeen, fid);
            // Bounded latency: if an old incomplete frame is more than 2 frame IDs behind, discard it.
            for (auto it = assembling.begin(); it != assembling.end();) {
                if (it->first + 2 < newestFrameSeen) { ++incompleteDropped; it = assembling.erase(it); }
                else ++it;
            }

            auto it = assembling.find(fid);
            if (it == assembling.end()) it = assembling.emplace(fid, FrameAssembly(cnt)).first;
            if (it->second.packetCount != cnt) { ++bad; assembling.erase(it); continue; }
            it->second.add(idx, buf.data()+20, len, (flags & 0x01) != 0);
            if (!it->second.complete()) continue;

            auto frame = it->second.join();
            bool discontinuity = lastSubmitted && fid != lastSubmitted + 1;
            decoder->submit(fid, frame, discontinuity);
            lastSubmitted = fid;
            ++complete;
            assembling.erase(it);
        }

        decoder->finish();
        std::cout << "Summary: packets=" << packets
                  << " complete_frames=" << complete
                  << " stale_incomplete_dropped=" << incompleteDropped
                  << " decoder_frames=" << decoder->decodedFrames()
                  << " stream_changes=" << decoder->streamChanges()
                  << " backpressure=" << decoder->inputBackpressure()
                  << " dxgi_frames=" << decoder->dxgiFrames()
                  << " bad=" << bad << " rejected=" << rejected << "\n";

        closesocket(s);
        trace("before.decoder.reset");
        decoder.reset();
        trace("after.decoder.reset");
        WSACleanup();
        MFShutdown();
        CoUninitialize();
        trace("shutdown.complete");
        return 0;
    } catch (const std::exception& e) {
        trace(e.what());
        std::cerr << "Fatal: " << e.what() << "\n";
        return 1;
    }
}
