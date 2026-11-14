#include "hardware_video_pipeline.hpp"
#include "present_scheduler.hpp"

#include <d3d10_1.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <dxgi1_3.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wmcodecdsp.h>
#include <wrl/client.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
#include <utility>

using Microsoft::WRL::ComPtr;

namespace {

void checkHr(HRESULT hr, const char* what) {
    if (FAILED(hr)) {
        char buf[224];
        std::snprintf(buf, sizeof(buf), "%s failed: 0x%08lx", what,
                      static_cast<unsigned long>(hr));
        throw std::runtime_error(buf);
    }
}

double steadyNowMs() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string wideToUtf8(const wchar_t* text) {
    if (!text || !*text) return {};
    int count = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (count <= 1) return {};
    std::string out(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), count, nullptr, nullptr);
    out.pop_back();
    return out;
}

} // namespace

struct HardwareVideoPipeline::Impl {
    HWND hwnd = nullptr;
    UINT32 width = 0;
    UINT32 height = 0;
    UINT32 fps = 0;
    JerisVideoCodec codec = JerisVideoCodec::H264;
    Logger logger;

    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11VideoDevice> videoDevice;
    ComPtr<ID3D11VideoContext> videoContext;
    ComPtr<IMFDXGIDeviceManager> dxgiManager;
    UINT resetToken = 0;

    ComPtr<IDXGISwapChain1> swapChain;
    std::string presentMode = "waitable";
    UINT swapFlags = 0;
    HANDLE latencyHandle = nullptr;  // owned; closed in abandonD3DSafely()
    // Newest decoded frame. Held so it can be presented after a busy
    // Present() and drawn again on WM_PAINT / resize (FLIP_DISCARD leaves the
    // back buffer undefined after every present).
    ComPtr<IMFSample> lastSample;
    std::unique_ptr<jl::LatestFramePresenter> presenter;
    double renderMs = 0.0;
    UINT lastTextureW = 0;
    UINT lastTextureH = 0;
    UINT lastArraySize = 0;
    UINT lastArraySlice = 0;
    ComPtr<ID3D11Texture2D> backBuffer;
    ComPtr<ID3D11RenderTargetView> renderTarget;
    ComPtr<ID3D11VideoProcessorEnumerator> vpEnumerator;
    ComPtr<ID3D11VideoProcessor> videoProcessor;
    ComPtr<ID3D11VideoProcessorOutputView> outputView;
    UINT processorInputW = 0;
    UINT processorInputH = 0;
    UINT swapW = 0;
    UINT swapH = 0;
    UINT32 activeSourceW = 0;
    UINT32 activeSourceH = 0;
    UINT inputNominalRange = D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;

    ComPtr<IMFTransform> decoder;
    bool finished = false;
    bool sawDxgiSample = false;
    std::string adapter;
    std::string decoderFriendlyName;

    uint64_t decoded = 0;
    uint64_t droppedNonDxgi = 0;
    uint64_t outputChanges = 0;
    uint64_t backpressure = 0;
    uint64_t presentCalls = 0;
    double presentMsTotal = 0.0;
    double presentMsMax = 0.0;
    UINT maxFrameLatency = 0;  // 0 = no waitable object

    // Hidden window (minimized, empty client area, DXGI_STATUS_OCCLUDED):
    // no render, no present, no ResizeBuffers to 1x1. Occlusion is
    // re-tested with DXGI_PRESENT_TEST at most every kOcclusionRetestMs.
    static constexpr double kOcclusionRetestMs = 100.0;
    bool occluded = false;
    double occlusionTestMs = 0.0;
    double hiddenSinceMs = 0.0;
    uint64_t hiddenDropsAtStart = 0;
    uint64_t occludedPresents = 0;
    uint64_t hiddenPeriods = 0;

    // Slow GPU / decoder calls (>= kSlowCallMs) are logged with the step
    // name, so a stall in the stats line can be tied to one call.
    static constexpr double kSlowCallMs = 50.0;
    double lastSlowLogMs = -1e9;
    uint64_t slowSuppressed = 0;

    // Present -> vblank time from GetFrameStatistics (flip model). This is
    // the time a presented frame waited in the swap chain queue before it
    // reached the screen; max frame latency 2 can add up to one refresh.
    struct PresentStamp { UINT id = 0; LONGLONG qpc = 0; bool valid = false; };
    PresentStamp presentStamps[16];
    UINT lastStatsPresentCount = 0;
    LONGLONG qpcFreq = 0;
    bool frameStatsFailLogged = false;
    std::vector<float> displaySamples;  // taken by the owner (worker thread)

    Impl(HWND inHwnd, UINT32 inW, UINT32 inH, UINT32 inFps,
         JerisVideoCodec inCodec, Logger inLogger, std::string inPresentMode)
        : hwnd(inHwnd), width(inW), height(inH), fps(inFps), codec(inCodec),
          logger(std::move(inLogger)), presentMode(std::move(inPresentMode)) {
        activeSourceW = inW;
        activeSourceH = inH;
        jl::PresentOps ops;
        ops.latencyReady = [this] {
            return !latencyHandle || WaitForSingleObjectEx(latencyHandle, 0, FALSE) == WAIT_OBJECT_0;
        };
        ops.render = [this] {
            const double t0 = steadyNowMs();
            renderLastSample();
            noteSlow("render", steadyNowMs() - t0);
        };
        ops.present = [this] { return presentBackBuffer(); };
        ops.nowMs = [] { return steadyNowMs(); };
        LARGE_INTEGER freq{};
        if (QueryPerformanceFrequency(&freq)) qpcFreq = freq.QuadPart;
        presenter = std::make_unique<jl::LatestFramePresenter>(std::move(ops));
        try {
            createD3D();
            createSwapChain();
            createDecoder();
        } catch (...) {
            abandonD3DSafely();
            throw;
        }
    }

    ~Impl() {
        if (decoder && !finished) {
            decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        abandonD3DSafely();
    }

    void abandonD3DSafely() noexcept {
        if (presenter) presenter->clear();
        lastSample.Reset();
        if (latencyHandle) {
            CloseHandle(latencyHandle);
            latencyHandle = nullptr;
        }
        decoder.Reset();
        outputView.Reset();
        videoProcessor.Reset();
        vpEnumerator.Reset();
        renderTarget.Reset();
        backBuffer.Reset();
        swapChain.Reset();
        dxgiManager.Reset();
        videoContext.Reset();
        videoDevice.Reset();
        context.Reset();

        // An AMD test laptop previously exposed an AMD-driver teardown fault on the final
        // ID3D11Device::Release(). Retain one process-local reference so a GPU
        // fallback cannot crash while unwinding. Windows reclaims it at exit.
        if (device) (void)device.Detach();
    }

    void log(const std::string& message) {
        if (logger) logger(message);
    }

    // Log one slow call. At most one line per second, except calls of
    // 200 ms or more, which are always logged.
    void noteSlow(const char* step, double ms) {
        if (ms < kSlowCallMs) return;
        const double now = steadyNowMs();
        if (ms < 200.0 && now - lastSlowLogMs < 1000.0) {
            ++slowSuppressed;
            return;
        }
        lastSlowLogMs = now;
        std::ostringstream os;
        os.setf(std::ios::fixed);
        os.precision(1);
        os << "video.slow step=" << step << " ms=" << ms
           << " hidden=" << (presenter && presenter->hidden() ? 1 : 0)
           << " iconic=" << (IsIconic(hwnd) ? 1 : 0)
           << " suppressed=" << slowSuppressed;
        slowSuppressed = 0;
        log(os.str());
    }

    void createD3D() {
        UINT flags = D3D11_CREATE_DEVICE_VIDEO_SUPPORT | D3D11_CREATE_DEVICE_BGRA_SUPPORT;
        D3D_FEATURE_LEVEL requested[] = {
            D3D_FEATURE_LEVEL_11_1,
            D3D_FEATURE_LEVEL_11_0,
            D3D_FEATURE_LEVEL_10_1,
            D3D_FEATURE_LEVEL_10_0,
        };
        D3D_FEATURE_LEVEL actual{};
        HRESULT hr = D3D11CreateDevice(
            nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
            requested, ARRAYSIZE(requested), D3D11_SDK_VERSION,
            &device, &actual, &context);
        if (hr == E_INVALIDARG) {
            hr = D3D11CreateDevice(
                nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags,
                requested + 1, ARRAYSIZE(requested) - 1, D3D11_SDK_VERSION,
                &device, &actual, &context);
        }
        checkHr(hr, "D3D11CreateDevice");
        checkHr(device.As(&videoDevice), "QI ID3D11VideoDevice");
        checkHr(context.As(&videoContext), "QI ID3D11VideoContext");
        ComPtr<ID3D10Multithread> multithread;
        if (SUCCEEDED(device.As(&multithread))) {
            multithread->SetMultithreadProtected(TRUE);
            log("gpu.multithread_protection=enabled");
        }
        checkHr(MFCreateDXGIDeviceManager(&resetToken, &dxgiManager), "MFCreateDXGIDeviceManager");
        checkHr(dxgiManager->ResetDevice(device.Get(), resetToken), "DXGI manager ResetDevice");

        ComPtr<IDXGIDevice> dxgiDevice;
        ComPtr<IDXGIAdapter> dxgiAdapter;
        checkHr(device.As(&dxgiDevice), "QI IDXGIDevice");
        checkHr(dxgiDevice->GetAdapter(&dxgiAdapter), "GetAdapter");
        DXGI_ADAPTER_DESC desc{};
        if (SUCCEEDED(dxgiAdapter->GetDesc(&desc))) adapter = wideToUtf8(desc.Description);

        std::ostringstream os;
        os << "gpu.device=created feature_level=0x" << std::hex << static_cast<unsigned>(actual)
           << std::dec << " adapter=\"" << adapter << "\"";
        log(os.str());
    }

    void createSwapChain() {
        ComPtr<IDXGIDevice> dxgiDevice;
        ComPtr<IDXGIAdapter> dxgiAdapter;
        ComPtr<IDXGIFactory2> factory;
        checkHr(device.As(&dxgiDevice), "QI IDXGIDevice for swapchain");
        checkHr(dxgiDevice->GetAdapter(&dxgiAdapter), "GetAdapter for swapchain");
        checkHr(dxgiAdapter->GetParent(IID_PPV_ARGS(&factory)), "GetParent IDXGIFactory2");

        RECT rc{};
        GetClientRect(hwnd, &rc);
        UINT cw = std::max<LONG>(1, rc.right - rc.left);
        UINT ch = std::max<LONG>(1, rc.bottom - rc.top);

        DXGI_SWAP_CHAIN_DESC1 sd{};
        sd.Width = cw;
        sd.Height = ch;
        sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
        sd.SampleDesc.Count = 1;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        // 3 buffers: one on screen, one queued for the next vsync, one free
        // to draw into. With 2 the only spare buffer is often still queued,
        // and DO_NOT_WAIT presents fail with WAS_STILL_DRAWING.
        sd.BufferCount = 3;
        sd.Scaling = DXGI_SCALING_STRETCH;
        sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        sd.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        const bool wantWaitable = presentMode != "nowait";
        sd.Flags = wantWaitable ? DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT : 0;
        HRESULT createHr = factory->CreateSwapChainForHwnd(device.Get(), hwnd, &sd, nullptr, nullptr, &swapChain);
        if (FAILED(createHr) && sd.Flags) {
            log("present.waitable=create_failed fallback=nowait");
            sd.Flags = 0;
            createHr = factory->CreateSwapChainForHwnd(device.Get(), hwnd, &sd, nullptr, nullptr, &swapChain);
        }
        checkHr(createHr, "CreateSwapChainForHwnd");
        swapFlags = sd.Flags;
        if (swapFlags & DXGI_SWAP_CHAIN_FLAG_FRAME_LATENCY_WAITABLE_OBJECT) {
            // Latency 2 (default): two frames may be queued for the screen,
            // so a burst of two decoded frames inside one refresh (network
            // jitter at 50-60 fps content) is shown instead of replacing
            // the first one. "waitable1" keeps the G2 behaviour (latency 1).
            const UINT wantLatency = presentMode == "waitable1" ? 1 : 2;
            ComPtr<IDXGISwapChain2> swapChain2;
            if (SUCCEEDED(swapChain.As(&swapChain2)) &&
                SUCCEEDED(swapChain2->SetMaximumFrameLatency(wantLatency))) {
                latencyHandle = swapChain2->GetFrameLatencyWaitableObject();
                if (latencyHandle) maxFrameLatency = wantLatency;
            }
            if (!latencyHandle) log("present.waitable=unavailable fallback=nowait");
        }
        factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
        swapW = cw;
        swapH = ch;
        rebuildOutputResources(cw, ch);
        log("present.path=d3d11-video-processor");
        {
            std::ostringstream os;
            os << "present.swapchain buffers=3 mode=" << (latencyHandle ? "waitable" : "nowait")
               << " max_frame_latency=" << maxFrameLatency
               << " requested=" << presentMode;
            log(os.str());
        }
    }

    void rebuildOutputResources(UINT outW, UINT outH) {
        outputView.Reset();
        renderTarget.Reset();
        backBuffer.Reset();
        videoProcessor.Reset();
        vpEnumerator.Reset();

        checkHr(swapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer)), "SwapChain GetBuffer");
        checkHr(device->CreateRenderTargetView(backBuffer.Get(), nullptr, &renderTarget),
                "CreateRenderTargetView");

        if (processorInputW == 0 || processorInputH == 0) return;

        D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
        content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
        content.InputFrameRate.Numerator = fps;
        content.InputFrameRate.Denominator = 1;
        content.InputWidth = processorInputW;
        content.InputHeight = processorInputH;
        content.OutputFrameRate.Numerator = fps;
        content.OutputFrameRate.Denominator = 1;
        content.OutputWidth = outW;
        content.OutputHeight = outH;
        content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
        checkHr(videoDevice->CreateVideoProcessorEnumerator(&content, &vpEnumerator),
                "CreateVideoProcessorEnumerator");
        checkHr(videoDevice->CreateVideoProcessor(vpEnumerator.Get(), 0, &videoProcessor),
                "CreateVideoProcessor");

        D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC outDesc{};
        outDesc.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
        outDesc.Texture2D.MipSlice = 0;
        checkHr(videoDevice->CreateVideoProcessorOutputView(
                    backBuffer.Get(), vpEnumerator.Get(), &outDesc, &outputView),
                "CreateVideoProcessorOutputView");

        videoContext->VideoProcessorSetStreamFrameFormat(
            videoProcessor.Get(), 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
        videoContext->VideoProcessorSetStreamAutoProcessingMode(videoProcessor.Get(), 0, FALSE);

        D3D11_VIDEO_PROCESSOR_COLOR_SPACE inputColor{};
        inputColor.YCbCr_Matrix = 1; // BT.709
        inputColor.Nominal_Range = inputNominalRange;
        videoContext->VideoProcessorSetStreamColorSpace(videoProcessor.Get(), 0, &inputColor);

        D3D11_VIDEO_PROCESSOR_COLOR_SPACE outputColor{};
        outputColor.RGB_Range = 0; // full RGB output
        videoContext->VideoProcessorSetOutputColorSpace(videoProcessor.Get(), &outputColor);
    }

    void ensureProcessor(UINT inputW, UINT inputH) {
        RECT rc{};
        GetClientRect(hwnd, &rc);
        UINT outW = std::max<LONG>(1, rc.right - rc.left);
        UINT outH = std::max<LONG>(1, rc.bottom - rc.top);

        const bool inputChanged = processorInputW != inputW || processorInputH != inputH;
        if (outW != swapW || outH != swapH) {
            const double t0 = steadyNowMs();
            const UINT fromW = swapW, fromH = swapH;
            outputView.Reset();
            renderTarget.Reset();
            backBuffer.Reset();
            videoProcessor.Reset();
            vpEnumerator.Reset();
            checkHr(swapChain->ResizeBuffers(0, outW, outH, DXGI_FORMAT_UNKNOWN, swapFlags),
                    "SwapChain ResizeBuffers");
            swapW = outW;
            swapH = outH;
            processorInputW = inputW;
            processorInputH = inputH;
            rebuildOutputResources(outW, outH);
            const double ms = steadyNowMs() - t0;
            std::ostringstream os;
            os.setf(std::ios::fixed);
            os.precision(1);
            os << "present.resize from=" << fromW << "x" << fromH << " to=" << outW << "x" << outH
               << " ms=" << ms << " iconic=" << (IsIconic(hwnd) ? 1 : 0);
            log(os.str());
        } else if (inputChanged || !videoProcessor || !outputView) {
            processorInputW = inputW;
            processorInputH = inputH;
            rebuildOutputResources(outW, outH);
        }
    }

    // Throws (so the viewer falls back to the CPU path) when the decoder
    // output is not a DXGI NV12 surface. Same checks the old present did.
    void validateSample(IMFSample* sample) {
        ComPtr<IMFMediaBuffer> mediaBuffer;
        checkHr(sample->GetBufferByIndex(0, &mediaBuffer), "GetBufferByIndex");
        ComPtr<IMFDXGIBuffer> dxgiBuffer;
        if (FAILED(mediaBuffer.As(&dxgiBuffer))) {
            ++droppedNonDxgi;
            throw std::runtime_error("hardware decoder returned a non-DXGI output sample");
        }
        sawDxgiSample = true;
        ComPtr<ID3D11Texture2D> texture;
        checkHr(dxgiBuffer->GetResource(IID_PPV_ARGS(&texture)), "DXGI buffer GetResource");
        D3D11_TEXTURE2D_DESC td{};
        texture->GetDesc(&td);
        if (td.Format != DXGI_FORMAT_NV12) {
            ++droppedNonDxgi;
            throw std::runtime_error("hardware decoder output is not DXGI_FORMAT_NV12");
        }
    }

    // A new decoded frame: it becomes the newest frame and is presented now
    // if the swap chain can take it, otherwise on a later servicePresent().
    void onDecodedSample(IMFSample* sample) {
        if (!sample) return;
        // The main window is destroyed before the final decoder drain when
        // the user closes Jerislink. Do not touch/resize the swapchain after
        // the HWND is gone; the remaining decoded frames can be discarded
        // during shutdown without being treated as a GPU runtime failure.
        if (!IsWindow(hwnd) || !swapChain) return;
        validateSample(sample);
        lastSample = sample;  // AddRef; the previous newest frame is released
        updateHidden();
        presenter->onDecoded();
    }

    bool clientSizeChanged() const {
        RECT rc{};
        GetClientRect(hwnd, &rc);
        const UINT outW = std::max<LONG>(1, rc.right - rc.left);
        const UINT outH = std::max<LONG>(1, rc.bottom - rc.top);
        return outW != swapW || outH != swapH;
    }

    // Minimized / empty client area / occluded: stop rendering and
    // presenting until the window can be seen again. Cheap when visible.
    void updateHidden() {
        const char* reason = nullptr;
        if (IsIconic(hwnd)) {
            reason = "minimized";
        } else {
            RECT rc{};
            GetClientRect(hwnd, &rc);
            if (rc.right - rc.left <= 0 || rc.bottom - rc.top <= 0) reason = "empty_client";
        }
        const double now = steadyNowMs();
        if (!reason && occluded) {
            if (now - occlusionTestMs >= kOcclusionRetestMs) {
                occlusionTestMs = now;
                // Microsoft's pattern for leaving the occluded idle state.
                const HRESULT hr = swapChain->Present(0, DXGI_PRESENT_TEST);
                if (hr != DXGI_STATUS_OCCLUDED) occluded = false;
            }
            if (occluded) reason = "occluded";
        }
        const bool hidden = reason != nullptr;
        if (hidden == presenter->hidden()) return;
        std::ostringstream os;
        os.setf(std::ios::fixed);
        os.precision(1);
        if (hidden) {
            ++hiddenPeriods;
            hiddenSinceMs = now;
            hiddenDropsAtStart = presenter->counters().hiddenDrops;
            os << "present.hidden=on reason=" << reason;
        } else {
            os << "present.hidden=off after_ms=" << (now - hiddenSinceMs)
               << " frames_not_shown=" << (presenter->counters().hiddenDrops - hiddenDropsAtStart);
        }
        presenter->setHidden(hidden);
        log(os.str());
    }

    void servicePresent() {
        if (!swapChain || !IsWindow(hwnd)) return;
        updateHidden();
        if (!presenter->wantsService()) return;
        // A frame drawn before a resize must be drawn again at the new size.
        if (clientSizeChanged()) presenter->onBuffersLost();
        presenter->service();
    }

    void repaint() {
        if (!swapChain || !lastSample || !IsWindow(hwnd)) return;
        updateHidden();
        presenter->onRepaint();
    }

    // Draw lastSample into the current back buffer (no present).
    void renderLastSample() {
        IMFSample* sample = lastSample.Get();
        if (!sample) throw std::runtime_error("present: no frame to render");
        ComPtr<IMFMediaBuffer> mediaBuffer;
        checkHr(sample->GetBufferByIndex(0, &mediaBuffer), "GetBufferByIndex");
        ComPtr<IMFDXGIBuffer> dxgiBuffer;
        checkHr(mediaBuffer.As(&dxgiBuffer), "QI IMFDXGIBuffer");

        ComPtr<ID3D11Texture2D> texture;
        checkHr(dxgiBuffer->GetResource(IID_PPV_ARGS(&texture)), "DXGI buffer GetResource");
        UINT subresource = 0;
        checkHr(dxgiBuffer->GetSubresourceIndex(&subresource), "GetSubresourceIndex");

        D3D11_TEXTURE2D_DESC td{};
        texture->GetDesc(&td);
        const UINT arraySlice = td.MipLevels ? subresource / td.MipLevels : 0;
        ensureProcessor(td.Width, td.Height);

        D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC inDesc{};
        inDesc.FourCC = 0;
        inDesc.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
        inDesc.Texture2D.MipSlice = 0;
        inDesc.Texture2D.ArraySlice = arraySlice;
        ComPtr<ID3D11VideoProcessorInputView> inputView;
        checkHr(videoDevice->CreateVideoProcessorInputView(
                    texture.Get(), vpEnumerator.Get(), &inDesc, &inputView),
                "CreateVideoProcessorInputView");

        const float black[4] = {0.f, 0.f, 0.f, 1.f};
        context->ClearRenderTargetView(renderTarget.Get(), black);

        UINT32 sourceW = activeSourceW ? activeSourceW : width;
        UINT32 sourceH = activeSourceH ? activeSourceH : height;
        sourceW = std::min<UINT32>(sourceW, td.Width);
        sourceH = std::min<UINT32>(sourceH, td.Height);
        RECT sourceRect{0, 0, static_cast<LONG>(sourceW), static_cast<LONG>(sourceH)};
        RECT targetRect{0, 0, static_cast<LONG>(swapW), static_cast<LONG>(swapH)};
        const double srcAspect = static_cast<double>(sourceW) / std::max<UINT32>(1, sourceH);
        if (static_cast<double>(swapW) / std::max<UINT>(1, swapH) > srcAspect) {
            LONG drawW = std::max<LONG>(1, static_cast<LONG>(swapH * srcAspect));
            targetRect.left = (static_cast<LONG>(swapW) - drawW) / 2;
            targetRect.right = targetRect.left + drawW;
        } else {
            LONG drawH = std::max<LONG>(1, static_cast<LONG>(swapW / srcAspect));
            targetRect.top = (static_cast<LONG>(swapH) - drawH) / 2;
            targetRect.bottom = targetRect.top + drawH;
        }
        videoContext->VideoProcessorSetStreamSourceRect(videoProcessor.Get(), 0, TRUE, &sourceRect);
        videoContext->VideoProcessorSetStreamDestRect(videoProcessor.Get(), 0, TRUE, &targetRect);

        D3D11_VIDEO_PROCESSOR_STREAM stream{};
        stream.Enable = TRUE;
        stream.OutputIndex = 0;
        stream.InputFrameOrField = 0;
        stream.PastFrames = 0;
        stream.FutureFrames = 0;
        stream.pInputSurface = inputView.Get();

        auto t0 = std::chrono::steady_clock::now();
        checkHr(videoContext->VideoProcessorBlt(
                    videoProcessor.Get(), outputView.Get(), 0, 1, &stream),
                "VideoProcessorBlt");
        renderMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        lastTextureW = td.Width;
        lastTextureH = td.Height;
        lastArraySize = td.ArraySize;
        lastArraySlice = arraySlice;
    }

    // Non-blocking present of the rendered back buffer.
    jl::PresentResult presentBackBuffer() {
        auto t0 = std::chrono::steady_clock::now();
        HRESULT presentHr = swapChain->Present(0, DXGI_PRESENT_DO_NOT_WAIT);
        if (presentHr == DXGI_ERROR_WAS_STILL_DRAWING) return jl::PresentResult::Busy;
        checkHr(presentHr, "SwapChain Present");
        HRESULT removed = device->GetDeviceRemovedReason();
        if (FAILED(removed)) checkHr(removed, "D3D device removed");
        const double callMs = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        noteSlow("present", callMs);
        if (presentHr == DXGI_STATUS_OCCLUDED) {
            // Not visible: stop presenting until DXGI_PRESENT_TEST says
            // otherwise (updateHidden).
            ++occludedPresents;
            if (!occluded) {
                occluded = true;
                occlusionTestMs = steadyNowMs();
            }
        } else {
            sampleFrameStatistics();
        }

        double ms = renderMs + callMs;
        ++presentCalls;
        presentMsTotal += ms;
        presentMsMax = std::max(presentMsMax, ms);

        if (presentCalls == 1) {
            std::ostringstream os;
            os << "FIRST_PRESENT d3d11-video-processor texture=" << lastTextureW << "x" << lastTextureH
               << " array=" << lastArraySize << " slice=" << lastArraySlice;
            log(os.str());
        }
        return jl::PresentResult::Ok;
    }

    // After a successful present: remember its present id and QPC time,
    // then read the newest frame statistics. When they describe a frame we
    // stamped, record present -> vblank in ms.
    void sampleFrameStatistics() {
        if (!qpcFreq) return;
        LARGE_INTEGER now{};
        QueryPerformanceCounter(&now);
        UINT id = 0;
        if (SUCCEEDED(swapChain->GetLastPresentCount(&id))) {
            PresentStamp& slot = presentStamps[id % 16];
            slot.id = id;
            slot.qpc = now.QuadPart;
            slot.valid = true;
        }
        DXGI_FRAME_STATISTICS st{};
        const HRESULT hr = swapChain->GetFrameStatistics(&st);
        if (FAILED(hr)) {
            if (!frameStatsFailLogged && hr != DXGI_ERROR_FRAME_STATISTICS_DISJOINT) {
                frameStatsFailLogged = true;
                char buf[96];
                std::snprintf(buf, sizeof(buf), "present.frame_stats=unavailable hr=0x%08lx",
                              static_cast<unsigned long>(hr));
                log(buf);
            }
            return;
        }
        if (st.PresentCount == lastStatsPresentCount) return;
        lastStatsPresentCount = st.PresentCount;
        // SyncQPCTime is the vblank of PresentRefreshCount only when the
        // two refresh counts match.
        if (st.SyncRefreshCount != st.PresentRefreshCount) return;
        const PresentStamp& slot = presentStamps[st.PresentCount % 16];
        if (!slot.valid || slot.id != st.PresentCount) return;
        const LONGLONG delta = st.SyncQPCTime.QuadPart - slot.qpc;
        if (delta < 0) return;
        const double ms = static_cast<double>(delta) * 1000.0 / static_cast<double>(qpcFreq);
        if (ms > 1000.0) return;
        if (displaySamples.size() < (1u << 14)) displaySamples.push_back(static_cast<float>(ms));
    }

    void createDecoder() {
        decoder = createJerisMfDecoder(codec, true, &decoderFriendlyName);
        ComPtr<IMFAttributes> attrs;
        checkHr(decoder->GetAttributes(&attrs), "decoder GetAttributes");
        UINT32 d3dAware = FALSE;
        if (FAILED(attrs->GetUINT32(MF_SA_D3D11_AWARE, &d3dAware)) || !d3dAware) {
            throw std::runtime_error("Media Foundation decoder is not D3D11-aware");
        }
        attrs->SetUINT32(MF_LOW_LATENCY, TRUE);
        checkHr(decoder->ProcessMessage(
                    MFT_MESSAGE_SET_D3D_MANAGER,
                    reinterpret_cast<ULONG_PTR>(dxgiManager.Get())),
                "SET_D3D_MANAGER");

        ComPtr<IMFMediaType> input;
        checkHr(MFCreateMediaType(&input), "MFCreateMediaType input");
        checkHr(input->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "input major type");
        checkHr(input->SetGUID(MF_MT_SUBTYPE, jerisVideoCodecInputSubtype(codec)), "input subtype");
        checkHr(MFSetAttributeSize(input.Get(), MF_MT_FRAME_SIZE, width, height), "input frame size");
        checkHr(MFSetAttributeRatio(input.Get(), MF_MT_FRAME_RATE, fps, 1), "input frame rate");
        checkHr(input->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive), "input interlace");
        checkHr(decoder->SetInputType(0, input.Get(), 0), "SetInputType");
        setOutputType();
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0), "BEGIN_STREAMING");
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0), "START_OF_STREAM");
        log("decoder.d3d11_aware=YES");
        log(std::string("decoder.mft=") + decoderFriendlyName);
        log(std::string("decoder.backend=mf-") + jerisVideoCodecName(codec) + "-dxva-d3d11");
    }

    void setOutputType() {
        ComPtr<IMFMediaType> chosen;
        for (DWORD i = 0;; ++i) {
            ComPtr<IMFMediaType> type;
            HRESULT hr = decoder->GetOutputAvailableType(0, i, &type);
            if (hr == MF_E_NO_MORE_TYPES) break;
            checkHr(hr, "GetOutputAvailableType");
            GUID subtype{};
            if (SUCCEEDED(type->GetGUID(MF_MT_SUBTYPE, &subtype)) && subtype == MFVideoFormat_NV12) {
                chosen = type;
                break;
            }
        }
        if (!chosen) throw std::runtime_error("hardware decoder did not offer NV12 output");
        checkHr(decoder->SetOutputType(0, chosen.Get(), 0), "SetOutputType NV12");

        UINT32 mfNominalRange = MFNominalRange_16_235;
        if (FAILED(chosen->GetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, &mfNominalRange))) {
            mfNominalRange = MFNominalRange_16_235;
        }
        inputNominalRange = (mfNominalRange == MFNominalRange_0_255)
            ? D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255
            : D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;
        {
            std::ostringstream rangeOs;
            rangeOs << "decoder.nominal_range="
                    << (mfNominalRange == MFNominalRange_0_255 ? "0-255" : "16-235")
                    << " d3d11=" << inputNominalRange;
            log(rangeOs.str());
        }
        UINT32 mtW = 0, mtH = 0;
        (void)MFGetAttributeSize(chosen.Get(), MF_MT_FRAME_SIZE, &mtW, &mtH);

        UINT32 displayW = mtW;
        UINT32 displayH = mtH;
        MFVideoArea aperture{};
        UINT32 apertureBytes = 0;
        auto readAperture = [&](const GUID& key) -> bool {
            apertureBytes = 0;
            HRESULT apertureHr = chosen->GetBlob(
                key,
                reinterpret_cast<UINT8*>(&aperture),
                static_cast<UINT32>(sizeof(aperture)),
                &apertureBytes);
            if (FAILED(apertureHr) || apertureBytes != sizeof(aperture)) return false;
            if (aperture.Area.cx <= 0 || aperture.Area.cy <= 0) return false;
            displayW = static_cast<UINT32>(aperture.Area.cx);
            displayH = static_cast<UINT32>(aperture.Area.cy);
            return true;
        };

        const bool haveAperture =
            readAperture(MF_MT_MINIMUM_DISPLAY_APERTURE) ||
            readAperture(MF_MT_GEOMETRIC_APERTURE) ||
            readAperture(MF_MT_PAN_SCAN_APERTURE);

        if (!haveAperture && mtW && mtH && width && height) {
            // Media Foundation commonly exposes an aligned NV12 surface height
            // (for example 990 -> 992 or 1800 -> 1808). When explicit display
            // aperture metadata is absent, preserve the stream's original
            // display aspect and trim only a small alignment tail.
            const double baseAspect = static_cast<double>(width) / height;
            const UINT32 inferredH = static_cast<UINT32>(
                std::llround(static_cast<double>(mtW) / baseAspect));
            if (inferredH > 0 && inferredH <= mtH && (mtH - inferredH) <= 16) {
                displayW = mtW;
                displayH = inferredH;
            }
        }

        if (displayW && displayH &&
            (displayW != activeSourceW || displayH != activeSourceH)) {
            activeSourceW = displayW;
            activeSourceH = displayH;
            std::ostringstream sourceOs;
            sourceOs << "present.source_active=" << activeSourceW << "x" << activeSourceH
                     << " surface=" << mtW << "x" << mtH;
            log(sourceOs.str());
        }
        std::ostringstream os;
        os << "decoder.output=DXGI-NV12 " << mtW << "x" << mtH;
        log(os.str());
    }

    void drain() {
        for (;;) {
            MFT_OUTPUT_STREAM_INFO osi{};
            checkHr(decoder->GetOutputStreamInfo(0, &osi), "GetOutputStreamInfo");
            if ((osi.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) == 0 &&
                (osi.dwFlags & MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES) == 0) {
                throw std::runtime_error("D3D11 decoder requires caller output buffers; refusing unsafe GPU path");
            }
            MFT_OUTPUT_DATA_BUFFER out{};
            DWORD status = 0;
            const double t0 = steadyNowMs();
            HRESULT hr = decoder->ProcessOutput(0, 1, &out, &status);
            noteSlow("decoder_output", steadyNowMs() - t0);
            if (out.pEvents) out.pEvents->Release();
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) return;
            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                ++outputChanges;
                setOutputType();
                continue;
            }
            checkHr(hr, "decoder ProcessOutput");
            if (out.pSample) {
                ComPtr<IMFSample> sample;
                sample.Attach(out.pSample);  // released at scope end unless kept as lastSample
                ++decoded;
                onDecodedSample(sample.Get());
            }
        }
    }

    void submit(uint64_t frameId, const std::vector<uint8_t>& annexB, bool discontinuity) {
        ComPtr<IMFSample> sample;
        ComPtr<IMFMediaBuffer> buffer;
        checkHr(MFCreateSample(&sample), "MFCreateSample");
        checkHr(MFCreateMemoryBuffer(static_cast<DWORD>(annexB.size()), &buffer), "MFCreateMemoryBuffer");
        BYTE* dst = nullptr;
        DWORD maxLen = 0, curLen = 0;
        checkHr(buffer->Lock(&dst, &maxLen, &curLen), "buffer Lock");
        std::memcpy(dst, annexB.data(), annexB.size());
        buffer->Unlock();
        checkHr(buffer->SetCurrentLength(static_cast<DWORD>(annexB.size())), "SetCurrentLength");
        checkHr(sample->AddBuffer(buffer.Get()), "AddBuffer");
        const LONGLONG t = static_cast<LONGLONG>((frameId - 1) * 10000000ULL / fps);
        const LONGLONG d = static_cast<LONGLONG>(10000000ULL / fps);
        sample->SetSampleTime(t);
        sample->SetSampleDuration(d);
        if (discontinuity) sample->SetUINT32(MFSampleExtension_Discontinuity, TRUE);

        double t0 = steadyNowMs();
        HRESULT hr = decoder->ProcessInput(0, sample.Get(), 0);
        noteSlow("decoder_input", steadyNowMs() - t0);
        if (hr == MF_E_NOTACCEPTING) {
            ++backpressure;
            drain();
            t0 = steadyNowMs();
            hr = decoder->ProcessInput(0, sample.Get(), 0);
            noteSlow("decoder_input_retry", steadyNowMs() - t0);
        }
        checkHr(hr, "decoder ProcessInput");
        drain();
    }

    void resetForNewStream() {
        if (!decoder) return;
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0), "decoder flush");
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0), "decoder restart stream");
        log("decoder.stream_reset");
    }

    void finish() {
        if (finished) return;
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0), "NOTIFY_END_OF_STREAM");
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0), "COMMAND_DRAIN");
        drain();
        // Release the held frame before the decoder lets go of its surfaces.
        presenter->clear();
        lastSample.Reset();
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0), "NOTIFY_END_STREAMING");
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, 0), "CLEAR_D3D_MANAGER");
        finished = true;
    }
};

HardwareVideoPipeline::HardwareVideoPipeline(
    HWND hwnd, UINT32 width, UINT32 height, UINT32 fps,
    JerisVideoCodec codec, Logger logger, const std::string& presentMode)
    : impl_(std::make_unique<Impl>(hwnd, width, height, fps, codec, std::move(logger), presentMode)) {}

HardwareVideoPipeline::~HardwareVideoPipeline() = default;

void HardwareVideoPipeline::submit(uint64_t frameId, const std::vector<uint8_t>& annexB, bool discontinuity) {
    impl_->submit(frameId, annexB, discontinuity);
}
void HardwareVideoPipeline::resetForNewStream() { impl_->resetForNewStream(); }
void HardwareVideoPipeline::finish() { impl_->finish(); }
void HardwareVideoPipeline::abandon() noexcept {
    if (!impl_) return;
    impl_->finished = true;
    impl_->abandonD3DSafely();
}
uint64_t HardwareVideoPipeline::decodedFrames() const { return impl_->decoded; }
void HardwareVideoPipeline::servicePresent() { impl_->servicePresent(); }
void HardwareVideoPipeline::repaint() { impl_->repaint(); }
bool HardwareVideoPipeline::presentPending() const {
    // A frame held while the window is hidden does not need polling.
    return impl_->swapChain && impl_->presenter->wantsService();
}
HANDLE HardwareVideoPipeline::presentWaitHandle() const {
    if (!impl_->swapChain || !impl_->latencyHandle) return nullptr;
    return impl_->presenter->waitingForLatency() ? impl_->latencyHandle : nullptr;
}
void HardwareVideoPipeline::onPresentWaitSignaled() {
    if (!impl_->swapChain) return;
    impl_->presenter->onLatencySignalled();
}
uint64_t HardwareVideoPipeline::presented() const { return impl_->presenter->counters().presented; }
uint64_t HardwareVideoPipeline::busyDrops() const { return impl_->presenter->counters().busyDrops; }
uint64_t HardwareVideoPipeline::busyRetries() const { return impl_->presenter->counters().busyRetries; }
uint64_t HardwareVideoPipeline::repaints() const { return impl_->presenter->counters().repaints; }
uint64_t HardwareVideoPipeline::latencyTimeouts() const { return impl_->presenter->counters().latencyTimeouts; }
uint64_t HardwareVideoPipeline::hiddenDrops() const { return impl_->presenter->counters().hiddenDrops; }
uint64_t HardwareVideoPipeline::occludedPresents() const { return impl_->occludedPresents; }
uint64_t HardwareVideoPipeline::hiddenPeriods() const { return impl_->hiddenPeriods; }
UINT HardwareVideoPipeline::maxFrameLatency() const { return impl_->maxFrameLatency; }
void HardwareVideoPipeline::takeDisplayLatencyMs(std::vector<float>& out) {
    out.insert(out.end(), impl_->displaySamples.begin(), impl_->displaySamples.end());
    impl_->displaySamples.clear();
}
uint64_t HardwareVideoPipeline::nonDxgiDrops() const { return impl_->droppedNonDxgi; }
uint64_t HardwareVideoPipeline::streamChanges() const { return impl_->outputChanges; }
uint64_t HardwareVideoPipeline::inputBackpressure() const { return impl_->backpressure; }
double HardwareVideoPipeline::avgPresentMs() const {
    return impl_->presentCalls ? impl_->presentMsTotal / static_cast<double>(impl_->presentCalls) : 0.0;
}
double HardwareVideoPipeline::maxPresentMs() const { return impl_->presentMsMax; }
UINT32 HardwareVideoPipeline::activeWidth() const { return impl_->activeSourceW; }
UINT32 HardwareVideoPipeline::activeHeight() const { return impl_->activeSourceH; }
const std::string& HardwareVideoPipeline::adapterName() const { return impl_->adapter; }
const std::string& HardwareVideoPipeline::decoderName() const { return impl_->decoderFriendlyName; }
