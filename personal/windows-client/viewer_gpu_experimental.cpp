#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <wmcodecdsp.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi1_2.h>
#include <dxgi1_3.h>
#include <dxgi1_4.h>
#include <wrl/client.h>
#include "control_channel.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <stdlib.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
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
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "iphlpapi.lib")

using Microsoft::WRL::ComPtr;

static std::string tempLogPath(const char* filename) {
    char buf[MAX_PATH + 2]{};
    DWORD n = GetTempPathA(static_cast<DWORD>(sizeof(buf)), buf);
    if (n == 0 || n >= sizeof(buf)) return filename;
    return std::string(buf) + filename;
}
static const std::string kLogPath = tempLogPath("jerislink-viewer.log");
static const std::string kHistoryLogPath = tempLogPath("jerislink-viewer-history.log");
extern "C" const char* __asan_default_options() {
    return "log_path=shader-asan:abort_on_error=1";
}
static bool gWindowClosed = false;
static ControlChannel* gControl = nullptr;
static bool gViewerFocused = false;
static bool gHaveMouse = false;
static POINT gLastMouse{};

static uint16_t semanticKey(WPARAM vk) {
    switch (vk) {
    case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return 1;
    case VK_MENU: case VK_LMENU: case VK_RMENU: return 2;
    case VK_LWIN: case VK_RWIN: return 3;
    case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: return 4;
    default:
        if (vk >= 'A' && vk <= 'Z') return static_cast<uint16_t>(vk);
        return 0;
    }
}

static void releaseRemoteModifiers() {
    if (!gControl) return;
    for (uint16_t k = 1; k <= 4; ++k) gControl->sendKey(false, k);
}

static void logLine(const std::string& s) {
    std::ofstream f(kLogPath, std::ios::app);
    f << s << "\n";
    f.flush();
    std::ofstream h(kHistoryLogPath, std::ios::app);
    h << s << "\n";
    h.flush();
}

static void check(HRESULT hr, const char* what) {
    if (FAILED(hr)) {
        char buf[192];
        std::snprintf(buf, sizeof(buf), "%s failed: 0x%08lx", what, static_cast<unsigned long>(hr));
        throw std::runtime_error(buf);
    }
}

static std::optional<std::string> detectTailscaleIPv4() {
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size);
    }
    if (rc != NO_ERROR) return std::nullopt;

    for (auto* a = adapters; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto* sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            uint32_t host = ntohl(sin->sin_addr.S_un.S_addr);
            if ((host & 0xFFC00000u) != 0x64400000u) continue;
            char ip[32]{};
            std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                          (host >> 24) & 0xff, (host >> 16) & 0xff,
                          (host >> 8) & 0xff, host & 0xff);
            return std::string(ip);
        }
    }
    return std::nullopt;
}

struct Options {
    std::string bindIp;
    std::string sourceIp;
    uint16_t port = 38401;
    uint16_t controlPort = 38400;
    bool controlEnabled = true;
    std::string presentMode = "nowait";
    int idleTimeoutMs = 8000;
    int startupTimeoutMs = 180000;
    UINT32 width = 1760;
    UINT32 height = 990;
    UINT32 fps = 60;
    UINT32 windowWidth = 1280;
    UINT32 windowHeight = 720;
};

static std::string envValue(const char* name) {
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || value == nullptr) return {};
    std::string out(value);
    free(value);
    return out;
}

static std::optional<Options> parseArgs(int argc, char** argv) {
    Options o;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i];
        if (k == "--no-control") {
            o.controlEnabled = false;
            continue;
        }
        if (i + 1 >= argc) return std::nullopt;
        std::string v = argv[++i];
        if (k == "--bind-ip") o.bindIp = v;
        else if (k == "--source-ip") o.sourceIp = v;
        else if (k == "--port") o.port = static_cast<uint16_t>(std::stoi(v));
        else if (k == "--control-port") o.controlPort = static_cast<uint16_t>(std::stoi(v));
        else if (k == "--idle-timeout-ms") o.idleTimeoutMs = std::stoi(v);
        else if (k == "--startup-timeout-ms") o.startupTimeoutMs = std::stoi(v);
        else if (k == "--width") o.width = static_cast<UINT32>(std::stoul(v));
        else if (k == "--height") o.height = static_cast<UINT32>(std::stoul(v));
        else if (k == "--fps") o.fps = static_cast<UINT32>(std::stoul(v));
        else if (k == "--window-width") o.windowWidth = static_cast<UINT32>(std::stoul(v));
        else if (k == "--window-height") o.windowHeight = static_cast<UINT32>(std::stoul(v));
        else if (k == "--present-mode") o.presentMode = v;
        else return std::nullopt;
    }
    if (o.bindIp.empty()) {
        auto detected = detectTailscaleIPv4();
        if (!detected) return std::nullopt;
        o.bindIp = *detected;
    }
    if (o.sourceIp.empty()) o.sourceIp = envValue("JERISLINK_SOURCE_IP");
    if (o.sourceIp.empty()) return std::nullopt;
    if (o.presentMode != "waitable" && o.presentMode != "nowait") return std::nullopt;
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

static LRESULT CALLBACK ViewerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_SETFOCUS:
        gViewerFocused = true;
        gHaveMouse = false;
        return 0;
    case WM_KILLFOCUS:
        gViewerFocused = false;
        gHaveMouse = false;
        releaseRemoteModifiers();
        return 0;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN: {
        if (!gViewerFocused || !gControl) break;
        const uint16_t key = semanticKey(wParam);
        if (!key) break;
        const bool repeat = (lParam & (1LL << 30)) != 0;
        if (!repeat) gControl->sendKey(true, key);
        return 0;
    }
    case WM_KEYUP:
    case WM_SYSKEYUP: {
        if (!gViewerFocused || !gControl) break;
        const uint16_t key = semanticKey(wParam);
        if (!key) break;
        gControl->sendKey(false, key);
        return 0;
    }
    case WM_MOUSEMOVE: {
        if (!gViewerFocused || !gControl) break;
        POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
        if (gHaveMouse) {
            int dx = p.x - gLastMouse.x, dy = p.y - gLastMouse.y;
            dx = std::clamp(dx, -32767, 32767);
            dy = std::clamp(dy, -32767, 32767);
            if (dx || dy) gControl->sendMouseMove(static_cast<int16_t>(dx), static_cast<int16_t>(dy));
        }
        gLastMouse = p;
        gHaveMouse = true;
        return 0;
    }
    case WM_LBUTTONDOWN:
        if (gViewerFocused && gControl) { SetCapture(hwnd); gControl->sendMouseButton(0, true); return 0; }
        break;
    case WM_LBUTTONUP:
        if (gViewerFocused && gControl) { gControl->sendMouseButton(0, false); ReleaseCapture(); return 0; }
        break;
    case WM_RBUTTONDOWN:
        if (gViewerFocused && gControl) { SetCapture(hwnd); gControl->sendMouseButton(1, true); return 0; }
        break;
    case WM_RBUTTONUP:
        if (gViewerFocused && gControl) { gControl->sendMouseButton(1, false); ReleaseCapture(); return 0; }
        break;
    case WM_MBUTTONDOWN:
        if (gViewerFocused && gControl) { SetCapture(hwnd); gControl->sendMouseButton(2, true); return 0; }
        break;
    case WM_MBUTTONUP:
        if (gViewerFocused && gControl) { gControl->sendMouseButton(2, false); ReleaseCapture(); return 0; }
        break;
    case WM_MOUSEWHEEL: {
        if (gViewerFocused && gControl) {
            int delta = static_cast<short>(HIWORD(wParam));
            delta = std::clamp(delta / 3, -32767, 32767);
            gControl->sendScroll(0, static_cast<int16_t>(delta));
            return 0;
        }
        break;
    }
    case WM_MOUSEHWHEEL: {
        if (gViewerFocused && gControl) {
            int delta = static_cast<short>(HIWORD(wParam));
            delta = std::clamp(delta / 3, -32767, 32767);
            gControl->sendScroll(static_cast<int16_t>(delta), 0);
            return 0;
        }
        break;
    }
    case WM_CLOSE:
        gWindowClosed = true;
        releaseRemoteModifiers();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        gWindowClosed = true;
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static HWND createViewerWindow(UINT32 clientW, UINT32 clientH) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    HINSTANCE hi = GetModuleHandleW(nullptr);
    const wchar_t* cls = L"JerislinkViewerClass";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = ViewerWndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.lpszClassName = cls;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        throw std::runtime_error("RegisterClassExW failed");
    }

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    RECT r{0, 0, static_cast<LONG>(clientW), static_cast<LONG>(clientH)};
    AdjustWindowRect(&r, style, FALSE);
    HWND hwnd = CreateWindowExW(0, cls, L"Jerislink 0.0.4 - Live Viewer",
                                style, CW_USEDEFAULT, CW_USEDEFAULT,
                                r.right - r.left, r.bottom - r.top,
                                nullptr, nullptr, hi, nullptr);
    if (!hwnd) throw std::runtime_error("CreateWindowExW failed");
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    return hwnd;
}

static void pumpMessages() {
    MSG m{};
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        if (m.message == WM_QUIT) gWindowClosed = true;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

struct D3DState {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IMFDXGIDeviceManager> dxgiManager;
    UINT resetToken = 0;

    D3DState() {
        UINT flags = D3D11_CREATE_DEVICE_VIDEO_SUPPORT | D3D11_CREATE_DEVICE_BGRA_SUPPORT;
        D3D_FEATURE_LEVEL fl{};
        check(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                                nullptr, 0, D3D11_SDK_VERSION,
                                &device, &fl, &context), "D3D11CreateDevice");
        check(MFCreateDXGIDeviceManager(&resetToken, &dxgiManager), "MFCreateDXGIDeviceManager");
        check(dxgiManager->ResetDevice(device.Get(), resetToken), "DXGI manager ResetDevice");
    }

    ~D3DState() {
        // AMD driver 32.0.31041.1004 corrupts its heap on the final
        // ID3D11Device::Release(). Release the dependent objects normally,
        // but intentionally keep one device reference until process exit.
        // Windows reclaims the process resources, avoiding the broken driver
        // teardown path without leaking across viewer processes.
        dxgiManager.Reset();
        context.Reset();
        if (device) {
            (void)device.Detach();
        }
    }
};

class D3DPresenter {
public:
    D3DPresenter(D3DState& d3d, HWND hwnd, UINT32 srcW, UINT32 srcH, UINT32 outW, UINT32 outH, bool useWaitable)
        : d3d_(d3d), hwnd_(hwnd), srcW_(srcW), srcH_(srcH), outW_(outW), outH_(outH), useWaitable_(useWaitable) {
        createSwapChain();
        createShaderPipeline();
        logLine("present.path=nv12-shader-copy");
    }

    uint64_t presented() const { return presented_; }
    uint64_t busyDrops() const { return busyDrops_; }
    uint64_t nonDxgiDrops() const { return nonDxgiDrops_; }
    double avgPresentMs() const { return presentCalls_ ? presentMsTotal_ / double(presentCalls_) : 0.0; }
    double maxPresentMs() const { return presentMsMax_; }

    void present(IMFSample* sample) {
        if (!sample || gWindowClosed) return;

        ComPtr<IMFMediaBuffer> mb;
        if (FAILED(sample->GetBufferByIndex(0, &mb))) { ++nonDxgiDrops_; return; }
        ComPtr<IMFDXGIBuffer> dxgiBuf;
        if (FAILED(mb.As(&dxgiBuf))) { ++nonDxgiDrops_; return; }
        ComPtr<ID3D11Texture2D> tex;
        if (FAILED(dxgiBuf->GetResource(IID_PPV_ARGS(&tex)))) { ++nonDxgiDrops_; return; }
        UINT subresource = 0;
        dxgiBuf->GetSubresourceIndex(&subresource);

        D3D11_TEXTURE2D_DESC td{};
        tex->GetDesc(&td);
        if (td.Format != DXGI_FORMAT_NV12) {
            ++nonDxgiDrops_;
            return;
        }
        const UINT arraySlice = td.MipLevels ? subresource / td.MipLevels : 0;

        if (useWaitable_ && frameLatencyWaitable_) {
            DWORD wr = WaitForSingleObjectEx(frameLatencyWaitable_, 0, FALSE);
            if (wr != WAIT_OBJECT_0) {
                ++busyDrops_;
                return;
            }
        }

        ensureNv12Resources(td.Width, td.Height);

        // Decoder surfaces are DXGI_FORMAT_NV12 texture arrays with DECODER bind only.
        // Copy the active array slice into our own NV12 SHADER_RESOURCE texture entirely
        // on the GPU; no CPU readback is involved.
        d3d_.context->CopySubresourceRegion(
            nv12Copy_.Get(), 0, 0, 0, 0,
            tex.Get(), subresource, nullptr);

        ComPtr<ID3D11Texture2D> backBuffer;
        check(swapChain_->GetBuffer(0, IID_PPV_ARGS(&backBuffer)), "SwapChain GetBuffer current");
        ComPtr<ID3D11RenderTargetView> rtv;
        check(d3d_.device->CreateRenderTargetView(backBuffer.Get(), nullptr, &rtv),
              "CreateRenderTargetView current");

        const float black[4] = {0.f, 0.f, 0.f, 1.f};
        d3d_.context->ClearRenderTargetView(rtv.Get(), black);
        ID3D11RenderTargetView* rtvRaw = rtv.Get();
        d3d_.context->OMSetRenderTargets(1, &rtvRaw, nullptr);

        D3D11_VIEWPORT vp{};
        vp.TopLeftX = 0.f;
        vp.TopLeftY = 0.f;
        vp.Width = static_cast<float>(outW_);
        vp.Height = static_cast<float>(outH_);
        vp.MinDepth = 0.f;
        vp.MaxDepth = 1.f;
        d3d_.context->RSSetViewports(1, &vp);

        d3d_.context->IASetInputLayout(nullptr);
        d3d_.context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
        d3d_.context->VSSetShader(vertexShader_.Get(), nullptr, 0);
        d3d_.context->PSSetShader(pixelShader_.Get(), nullptr, 0);

        ID3D11ShaderResourceView* srvs[2] = {yView_.Get(), uvView_.Get()};
        d3d_.context->PSSetShaderResources(0, 2, srvs);
        ID3D11SamplerState* sampler = sampler_.Get();
        d3d_.context->PSSetSamplers(0, 1, &sampler);
        ID3D11Buffer* params = paramsBuffer_.Get();
        d3d_.context->PSSetConstantBuffers(0, 1, &params);

        d3d_.context->Draw(3, 0);

        // Avoid resource hazards before the next frame copies into nv12Copy_.
        ID3D11ShaderResourceView* nullSrvs[2] = {nullptr, nullptr};
        d3d_.context->PSSetShaderResources(0, 2, nullSrvs);
        d3d_.context->OMSetRenderTargets(0, nullptr, nullptr);

        auto presentStart = std::chrono::steady_clock::now();
        HRESULT hr = swapChain_->Present(0, useWaitable_ ? 0 : DXGI_PRESENT_DO_NOT_WAIT);
        double presentMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - presentStart).count();
        if (hr == DXGI_ERROR_WAS_STILL_DRAWING) {
            ++busyDrops_;
            return;
        }
        check(hr, "SwapChain Present");
        ++presented_;
        ++presentCalls_;
        presentMsTotal_ += presentMs;
        presentMsMax_ = std::max(presentMsMax_, presentMs);

        if (presented_ == 1) {
            std::ostringstream os;
            os << "FIRST_PRESENT texture=" << td.Width << "x" << td.Height
               << " format=" << static_cast<unsigned>(td.Format)
               << " array=" << td.ArraySize << " slice=" << arraySlice
               << " path=nv12-shader-copy";
            logLine(os.str());
        }
        if ((presented_ % 120) == 0) updateTitle();
    }

private:
    struct ShaderParams {
        float uvScaleX;
        float uvScaleY;
        float pad0;
        float pad1;
    };

    static ComPtr<ID3DBlob> compileShader(const char* source, const char* entry, const char* target) {
        ComPtr<ID3DBlob> code;
        ComPtr<ID3DBlob> errors;
        HRESULT hr = D3DCompile(
            source,
            std::strlen(source),
            "JerislinkInlineShader",
            nullptr,
            nullptr,
            entry,
            target,
            D3DCOMPILE_ENABLE_STRICTNESS | D3DCOMPILE_OPTIMIZATION_LEVEL3,
            0,
            &code,
            &errors);
        if (FAILED(hr)) {
            std::string msg = "D3DCompile failed";
            if (errors && errors->GetBufferPointer() && errors->GetBufferSize()) {
                msg += ": ";
                msg.append(static_cast<const char*>(errors->GetBufferPointer()), errors->GetBufferSize());
            }
            throw std::runtime_error(msg);
        }
        return code;
    }

    void createSwapChain() {
        ComPtr<IDXGIDevice> dxgiDevice;
        check(d3d_.device.As(&dxgiDevice), "QI IDXGIDevice");
        ComPtr<IDXGIAdapter> adapter;
        check(dxgiDevice->GetAdapter(&adapter), "GetAdapter");
        ComPtr<IDXGIFactory2> factory;
        check(adapter->GetParent(IID_PPV_ARGS(&factory)), "Get DXGI factory");

        DXGI_SWAP_CHAIN_DESC1 sd{};
        sd.Width = outW_;
        sd.Height = outH_;
        sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        sd.SampleDesc.Count = 1;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.BufferCount = 2;
        sd.Scaling = DXGI_SCALING_STRETCH;
        sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        sd.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT;

        check(factory->CreateSwapChainForHwnd(d3d_.device.Get(), hwnd_, &sd, nullptr, nullptr, &swapChain_),
              "CreateSwapChainForHwnd");
        factory->MakeWindowAssociation(hwnd_, DXGI_MWA_NO_ALT_ENTER);

        ComPtr<IDXGISwapChain2> sc2;
        if (SUCCEEDED(swapChain_.As(&sc2))) {
            sc2->SetMaximumFrameLatency(1);
            frameLatencyWaitable_ = sc2->GetFrameLatencyWaitableObject();
        }
    }

    void createShaderPipeline() {
        static const char* vsSource = R"MRVS(
struct VSOut {
    float4 pos : SV_POSITION;
    float2 uv  : TEXCOORD0;
};
VSOut main(uint id : SV_VertexID) {
    float2 uv = float2((id << 1) & 2u, id & 2u);
    VSOut o;
    o.pos = float4(uv * float2(2.0, -2.0) + float2(-1.0, 1.0), 0.0, 1.0);
    o.uv = uv;
    return o;
}
)MRVS";

        static const char* psSource = R"MRPS(
struct VSOut {
    float4 pos : SV_POSITION;
    float2 uv  : TEXCOORD0;
};
Texture2D<float>  yTex  : register(t0);
Texture2D<float2> uvTex : register(t1);
SamplerState linearSampler : register(s0);
cbuffer Params : register(b0) {
    float2 uvScale;
    float2 padding;
};
float4 main(VSOut input) : SV_TARGET {
    float2 uv = input.uv * uvScale;
    float y = yTex.Sample(linearSampler, uv).r;
    float2 c = uvTex.Sample(linearSampler, uv).rg - float2(0.5, 0.5);

    // ScreenCaptureKit source is 420v (video range). Use BT.709 conversion.
    float Y = max(0.0, (y - (16.0 / 255.0)) * (255.0 / 219.0));
    float3 rgb;
    rgb.r = Y + 1.792741 * c.y;
    rgb.g = Y - 0.213249 * c.x - 0.532909 * c.y;
    rgb.b = Y + 2.112402 * c.x;
    return float4(saturate(rgb), 1.0);
}
)MRPS";

        auto vs = compileShader(vsSource, "main", "vs_5_0");
        auto ps = compileShader(psSource, "main", "ps_5_0");
        check(d3d_.device->CreateVertexShader(vs->GetBufferPointer(), vs->GetBufferSize(), nullptr, &vertexShader_),
              "CreateVertexShader");
        check(d3d_.device->CreatePixelShader(ps->GetBufferPointer(), ps->GetBufferSize(), nullptr, &pixelShader_),
              "CreatePixelShader");

        D3D11_SAMPLER_DESC sd{};
        sd.Filter = D3D11_FILTER_MIN_MAG_LINEAR_MIP_POINT;
        sd.AddressU = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.AddressV = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.AddressW = D3D11_TEXTURE_ADDRESS_CLAMP;
        sd.ComparisonFunc = D3D11_COMPARISON_ALWAYS;
        sd.MinLOD = 0.f;
        sd.MaxLOD = D3D11_FLOAT32_MAX;
        check(d3d_.device->CreateSamplerState(&sd, &sampler_), "CreateSamplerState");

        D3D11_BUFFER_DESC bd{};
        bd.ByteWidth = sizeof(ShaderParams);
        bd.Usage = D3D11_USAGE_DEFAULT;
        bd.BindFlags = D3D11_BIND_CONSTANT_BUFFER;
        check(d3d_.device->CreateBuffer(&bd, nullptr, &paramsBuffer_), "Create shader params buffer");
    }

    void ensureNv12Resources(UINT width, UINT height) {
        if (nv12Copy_ && copyW_ == width && copyH_ == height) return;

        yView_.Reset();
        uvView_.Reset();
        nv12Copy_.Reset();

        D3D11_TEXTURE2D_DESC td{};
        td.Width = width;
        td.Height = height;
        td.MipLevels = 1;
        td.ArraySize = 1;
        td.Format = DXGI_FORMAT_NV12;
        td.SampleDesc.Count = 1;
        td.Usage = D3D11_USAGE_DEFAULT;
        td.BindFlags = D3D11_BIND_SHADER_RESOURCE;
        check(d3d_.device->CreateTexture2D(&td, nullptr, &nv12Copy_), "Create NV12 shader texture");

        D3D11_SHADER_RESOURCE_VIEW_DESC yDesc{};
        yDesc.Format = DXGI_FORMAT_R8_UNORM;
        yDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        yDesc.Texture2D.MostDetailedMip = 0;
        yDesc.Texture2D.MipLevels = 1;
        check(d3d_.device->CreateShaderResourceView(nv12Copy_.Get(), &yDesc, &yView_), "Create NV12 Y SRV");

        D3D11_SHADER_RESOURCE_VIEW_DESC uvDesc{};
        uvDesc.Format = DXGI_FORMAT_R8G8_UNORM;
        uvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
        uvDesc.Texture2D.MostDetailedMip = 0;
        uvDesc.Texture2D.MipLevels = 1;
        check(d3d_.device->CreateShaderResourceView(nv12Copy_.Get(), &uvDesc, &uvView_), "Create NV12 UV SRV");

        ShaderParams params{};
        params.uvScaleX = width ? static_cast<float>(srcW_) / static_cast<float>(width) : 1.f;
        params.uvScaleY = height ? static_cast<float>(srcH_) / static_cast<float>(height) : 1.f;
        d3d_.context->UpdateSubresource(paramsBuffer_.Get(), 0, nullptr, &params, 0, 0);

        copyW_ = width;
        copyH_ = height;

        std::ostringstream os;
        os << "shader.nv12_resource=" << width << "x" << height
           << " uvScale=" << params.uvScaleX << "," << params.uvScaleY;
        logLine(os.str());
    }

    void updateTitle() {
        wchar_t title[256];
        swprintf_s(title, L"Jerislink 0.0.4 - presented %llu | busy drops %llu",
                   static_cast<unsigned long long>(presented_),
                   static_cast<unsigned long long>(busyDrops_));
        SetWindowTextW(hwnd_, title);
    }

    D3DState& d3d_;
    HWND hwnd_ = nullptr;
    UINT32 srcW_, srcH_, outW_, outH_;
    ComPtr<IDXGISwapChain1> swapChain_;
    ComPtr<ID3D11VertexShader> vertexShader_;
    ComPtr<ID3D11PixelShader> pixelShader_;
    ComPtr<ID3D11SamplerState> sampler_;
    ComPtr<ID3D11Buffer> paramsBuffer_;
    ComPtr<ID3D11Texture2D> nv12Copy_;
    ComPtr<ID3D11ShaderResourceView> yView_;
    ComPtr<ID3D11ShaderResourceView> uvView_;
    UINT copyW_ = 0;
    UINT copyH_ = 0;
    bool useWaitable_ = true;
    HANDLE frameLatencyWaitable_ = nullptr;
    uint64_t presented_ = 0;
    uint64_t busyDrops_ = 0;
    uint64_t nonDxgiDrops_ = 0;
    uint64_t presentCalls_ = 0;
    double presentMsTotal_ = 0.0;
    double presentMsMax_ = 0.0;
};

class H264Decoder {
public:
    H264Decoder(D3DState& d3d, D3DPresenter& presenter, UINT32 width, UINT32 height, UINT32 fps)
        : d3d_(d3d), presenter_(presenter), width_(width), height_(height), fps_(fps) {
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

    void finish() {
        if (finished_) return;
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0), "NOTIFY_END_OF_STREAM");
        check(decoder_->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0), "COMMAND_DRAIN");
        drain();
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0), "NOTIFY_END_STREAMING");
        finished_ = true;
    }

private:
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
            if (odb.pSample) {
                ++decodedFrames_;
                presenter_.present(odb.pSample);
            }
            if (odb.pSample && odb.pSample != clientSample.Get()) odb.pSample->Release();
        }
    }

    void createDecoder() {
        check(CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                               IID_PPV_ARGS(&decoder_)), "CoCreate H264 decoder");
        ComPtr<IMFAttributes> attrs;
        if (SUCCEEDED(decoder_->GetAttributes(&attrs))) {
            UINT32 aware = FALSE;
            if (SUCCEEDED(attrs->GetUINT32(MF_SA_D3D11_AWARE, &aware)) && aware) {
                check(decoder_->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                      reinterpret_cast<ULONG_PTR>(d3d_.dxgiManager.Get())), "SET_D3D_MANAGER");
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
        setOutputType();
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0), "BEGIN_STREAMING");
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0), "START_OF_STREAM");
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

    D3DState& d3d_;
    D3DPresenter& presenter_;
    UINT32 width_, height_, fps_;
    ComPtr<IMFTransform> decoder_;
    bool d3dAware_ = false;
    bool finished_ = false;
    uint64_t decodedFrames_ = 0;
    uint64_t streamChanges_ = 0;
    uint64_t inputBackpressure_ = 0;
};

static int appMain(int argc, char** argv) {
    std::remove(kLogPath.c_str());
    logLine(std::string("viewer.start pid=") + std::to_string(GetCurrentProcessId()));
    auto parsed = parseArgs(argc, argv);
    if (!parsed) {
        logLine("usage error: no host address, no active Tailscale IPv4 address or invalid arguments");
        MessageBoxW(nullptr, L"Jerislink needs the Mac host address (--source-ip or the JERISLINK_SOURCE_IP environment variable) and an active Tailscale IPv4 address, or the command-line arguments are invalid.\n\nSet JERISLINK_SOURCE_IP to your Mac's Tailscale IPv4 address, connect Tailscale and try again.", L"Jerislink", MB_OK | MB_ICONERROR);
        return 2;
    }
    const Options o = *parsed;

    HRESULT coHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(coHr)) return 3;
    bool mfStarted = false;
    bool wsaStarted = false;
    try {
        check(MFStartup(MF_VERSION, MFSTARTUP_FULL), "MFStartup");
        mfStarted = true;
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) throw std::runtime_error("WSAStartup failed");
        wsaStarted = true;

        std::unique_ptr<ControlChannel> control;
        if (o.controlEnabled) {
            control = std::make_unique<ControlChannel>(o.bindIp, o.sourceIp, o.controlPort);
            gControl = control.get();
            double controlRtt = 0.0;
            if (control->ping(&controlRtt)) {
                std::ostringstream ctl;
                ctl << "control.connected rtt_ms=" << controlRtt;
                logLine(ctl.str());
            } else {
                logLine("control.initial_connect_failed; will reconnect on input");
            }
        } else {
            gControl = nullptr;
            logLine("control.disabled");
        }

        HWND hwnd = createViewerWindow(o.windowWidth, o.windowHeight);
        auto d3d = std::make_unique<D3DState>();
        const bool useWaitablePresent = (o.presentMode == "waitable");
        logLine(std::string("present.mode=") + o.presentMode);
        auto presenter = std::make_unique<D3DPresenter>(*d3d, hwnd, o.width, o.height, o.windowWidth, o.windowHeight, useWaitablePresent);
        auto decoder = std::make_unique<H264Decoder>(*d3d, *presenter, o.width, o.height, o.fps);

        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) throw std::runtime_error("socket failed");
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
        DWORD shortTimeout = 16;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&shortTimeout), sizeof(shortTimeout));

        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(o.port);
        if (inet_pton(AF_INET, o.bindIp.c_str(), &local.sin_addr) != 1 ||
            bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            closesocket(s);
            throw std::runtime_error("bind failed");
        }
        in_addr allowed{};
        if (inet_pton(AF_INET, o.sourceIp.c_str(), &allowed) != 1) {
            closesocket(s);
            throw std::runtime_error("bad source IP");
        }

        logLine(std::string("decoder.d3d11_aware=") + (decoder->hardwarePath() ? "YES" : "NO"));
        logLine("viewer.waiting_for_stream");

        std::unordered_map<uint64_t, FrameAssembly> assembling;
        uint64_t packets = 0, complete = 0, incompleteDropped = 0, bad = 0, rejected = 0;
        uint64_t newestFrameSeen = 0, lastSubmitted = 0;
        std::vector<uint8_t> buf(2048);
        auto start = std::chrono::steady_clock::now();
        auto lastPacket = start;
        bool gotAny = false;

        while (!gWindowClosed) {
            pumpMessages();
            if (gWindowClosed) break;

            sockaddr_in peer{}; int plen = sizeof(peer);
            int n = recvfrom(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&peer), &plen);
            auto now = std::chrono::steady_clock::now();
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) {
                    auto base = gotAny ? lastPacket : start;
                    const int timeoutMs = gotAny ? o.idleTimeoutMs : o.startupTimeoutMs;
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - base).count() >= timeoutMs) break;
                    continue;
                }
                closesocket(s);
                throw std::runtime_error("recvfrom failed");
            }
            gotAny = true;
            lastPacket = now;
            if (peer.sin_addr.s_addr != allowed.s_addr) { ++rejected; continue; }
            ++packets;
            if (n < 20 || std::memcmp(buf.data(), "MR02", 4) || buf[4] != 1) { ++bad; continue; }
            uint8_t flags = buf[5];
            uint64_t fid = be64(buf.data()+6);
            uint16_t idx = be16(buf.data()+14), cnt = be16(buf.data()+16), len = be16(buf.data()+18);
            if (!cnt || idx >= cnt || len != static_cast<uint16_t>(n-20)) { ++bad; continue; }

            newestFrameSeen = std::max(newestFrameSeen, fid);
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
        closesocket(s);
        pumpMessages();

        std::ostringstream summary;
        summary << "SUMMARY packets=" << packets
                << " complete_frames=" << complete
                << " decoded_frames=" << decoder->decodedFrames()
                << " presented_frames=" << presenter->presented()
                << " present_busy_drops=" << presenter->busyDrops()
                << " present_avg_ms=" << presenter->avgPresentMs()
                << " present_max_ms=" << presenter->maxPresentMs()
                << " non_dxgi_drops=" << presenter->nonDxgiDrops()
                << " stale_incomplete_dropped=" << incompleteDropped
                << " stream_changes=" << decoder->streamChanges()
                << " backpressure=" << decoder->inputBackpressure()
                << " control_events=" << (control ? control->sentEvents() : 0)
                << " control_failures=" << (control ? control->failures() : 0)
                << " bad=" << bad << " rejected=" << rejected;
        logLine(summary.str());
        gControl = nullptr;

        // Release all Media Foundation / D3D / control objects while their
        // runtimes are still initialized. Releasing them after MFShutdown or
        // CoUninitialize can AV inside the decoder or COM teardown.
        decoder.reset();
        presenter.reset();
        d3d.reset();
        control.reset();

        if (wsaStarted) { WSACleanup(); wsaStarted = false; }
        if (mfStarted) { MFShutdown(); mfStarted = false; }
        CoUninitialize();
        return 0;
    } catch (const std::exception& e) {
        gControl = nullptr;
        logLine(std::string("FATAL ") + e.what());
        MessageBoxA(nullptr, e.what(), "Jerislink", MB_OK | MB_ICONERROR);
        if (wsaStarted) WSACleanup();
        if (mfStarted) MFShutdown();
        CoUninitialize();
        return 1;
    }
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    return appMain(__argc, __argv);
}
