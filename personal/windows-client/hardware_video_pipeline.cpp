#include "hardware_video_pipeline.hpp"
#include "source_rect.hpp"

#include <d3d10_1.h>
#include <d3d11.h>
#include <dxgi1_2.h>
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
    ComPtr<ID3D11Texture2D> backBuffer;
    ComPtr<ID3D11RenderTargetView> renderTarget;
    ComPtr<ID3D11VideoProcessorEnumerator> vpEnumerator;
    ComPtr<ID3D11VideoProcessor> videoProcessor;
    ComPtr<ID3D11VideoProcessorOutputView> outputView;
    UINT processorInputW = 0;
    UINT processorInputH = 0;
    UINT swapW = 0;
    UINT swapH = 0;
    UINT32 activeSourceX = 0;
    UINT32 activeSourceY = 0;
    UINT32 activeSourceW = 0;
    UINT32 activeSourceH = 0;
    UINT inputNominalRange = D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;

    ComPtr<IMFTransform> decoder;
    bool finished = false;
    bool sawDxgiSample = false;
    std::string adapter;
    std::string decoderFriendlyName;

    uint64_t decoded = 0;
    uint64_t presentedFrames = 0;
    uint64_t droppedBusy = 0;
    uint64_t droppedNonDxgi = 0;
    uint64_t outputChanges = 0;
    uint64_t backpressure = 0;
    uint64_t presentCalls = 0;
    double presentMsTotal = 0.0;
    double presentMsMax = 0.0;

    Impl(HWND inHwnd, UINT32 inW, UINT32 inH, UINT32 inFps,
         JerisVideoCodec inCodec, Logger inLogger)
        : hwnd(inHwnd), width(inW), height(inH), fps(inFps), codec(inCodec),
          logger(std::move(inLogger)) {
        activeSourceW = inW;
        activeSourceH = inH;
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
        sd.BufferCount = 2;
        sd.Scaling = DXGI_SCALING_STRETCH;
        sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
        sd.AlphaMode = DXGI_ALPHA_MODE_IGNORE;
        checkHr(factory->CreateSwapChainForHwnd(device.Get(), hwnd, &sd, nullptr, nullptr, &swapChain),
                "CreateSwapChainForHwnd");
        factory->MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
        swapW = cw;
        swapH = ch;
        rebuildOutputResources(cw, ch);
        log("present.path=d3d11-video-processor");
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
            outputView.Reset();
            renderTarget.Reset();
            backBuffer.Reset();
            videoProcessor.Reset();
            vpEnumerator.Reset();
            checkHr(swapChain->ResizeBuffers(0, outW, outH, DXGI_FORMAT_UNKNOWN, 0),
                    "SwapChain ResizeBuffers");
            swapW = outW;
            swapH = outH;
            processorInputW = inputW;
            processorInputH = inputH;
            rebuildOutputResources(outW, outH);
        } else if (inputChanged || !videoProcessor || !outputView) {
            processorInputW = inputW;
            processorInputH = inputH;
            rebuildOutputResources(outW, outH);
        }
    }

    void presentSample(IMFSample* sample) {
        if (!sample) return;
        // The main window is destroyed before the final decoder drain when
        // the user closes Jerislink. Do not touch/resize the swapchain after
        // the HWND is gone; the remaining decoded frames can be discarded
        // during shutdown without being treated as a GPU runtime failure.
        if (!IsWindow(hwnd)) return;

        ComPtr<IMFMediaBuffer> mediaBuffer;
        checkHr(sample->GetBufferByIndex(0, &mediaBuffer), "GetBufferByIndex");
        ComPtr<IMFDXGIBuffer> dxgiBuffer;
        HRESULT dxgiHr = mediaBuffer.As(&dxgiBuffer);
        if (FAILED(dxgiHr)) {
            ++droppedNonDxgi;
            throw std::runtime_error("hardware decoder returned a non-DXGI output sample");
        }
        sawDxgiSample = true;

        ComPtr<ID3D11Texture2D> texture;
        checkHr(dxgiBuffer->GetResource(IID_PPV_ARGS(&texture)), "DXGI buffer GetResource");
        UINT subresource = 0;
        checkHr(dxgiBuffer->GetSubresourceIndex(&subresource), "GetSubresourceIndex");

        D3D11_TEXTURE2D_DESC td{};
        texture->GetDesc(&td);
        if (td.Format != DXGI_FORMAT_NV12) {
            ++droppedNonDxgi;
            throw std::runtime_error("hardware decoder output is not DXGI_FORMAT_NV12");
        }
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

        UINT32 sourceX = std::min<UINT32>(activeSourceX, td.Width - 1);
        UINT32 sourceY = std::min<UINT32>(activeSourceY, td.Height - 1);
        UINT32 sourceW = activeSourceW ? activeSourceW : width;
        UINT32 sourceH = activeSourceH ? activeSourceH : height;
        sourceW = std::min<UINT32>(sourceW, td.Width - sourceX);
        sourceH = std::min<UINT32>(sourceH, td.Height - sourceY);
        RECT sourceRect{static_cast<LONG>(sourceX), static_cast<LONG>(sourceY),
                        static_cast<LONG>(sourceX + sourceW), static_cast<LONG>(sourceY + sourceH)};
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
        HRESULT presentHr = swapChain->Present(0, DXGI_PRESENT_DO_NOT_WAIT);
        if (presentHr == DXGI_ERROR_WAS_STILL_DRAWING) {
            ++droppedBusy;
            return;
        }
        checkHr(presentHr, "SwapChain Present");
        HRESULT removed = device->GetDeviceRemovedReason();
        if (FAILED(removed)) checkHr(removed, "D3D device removed");

        double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        ++presentedFrames;
        ++presentCalls;
        presentMsTotal += ms;
        presentMsMax = std::max(presentMsMax, ms);

        if (presentedFrames == 1) {
            std::ostringstream os;
            os << "FIRST_PRESENT d3d11-video-processor texture=" << td.Width << "x" << td.Height
               << " array=" << td.ArraySize << " slice=" << arraySlice;
            log(os.str());
        }
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
            if (aperture.OffsetX.value < 0 || aperture.OffsetY.value < 0) return false;
            return true;
        };

        const bool haveAperture =
            readAperture(MF_MT_MINIMUM_DISPLAY_APERTURE) ||
            readAperture(MF_MT_GEOMETRIC_APERTURE) ||
            readAperture(MF_MT_PAN_SCAN_APERTURE);

        // width/height are the host framebuffer size from the VIDEO_CONFIG
        // ACK. The host encodes a 16-aligned frame with the picture centred
        // in it, so crop to that picture instead of scaling the bars in.
        const JerisSourceRect picked = jerisPickSourceRect(
            mtW, mtH, haveAperture,
            haveAperture ? static_cast<uint32_t>(aperture.OffsetX.value) : 0,
            haveAperture ? static_cast<uint32_t>(aperture.OffsetY.value) : 0,
            haveAperture ? static_cast<uint32_t>(aperture.Area.cx) : 0,
            haveAperture ? static_cast<uint32_t>(aperture.Area.cy) : 0,
            width, height);

        if (picked.w && picked.h &&
            (picked.x != activeSourceX || picked.y != activeSourceY ||
             picked.w != activeSourceW || picked.h != activeSourceH)) {
            activeSourceX = picked.x;
            activeSourceY = picked.y;
            activeSourceW = picked.w;
            activeSourceH = picked.h;
            std::ostringstream sourceOs;
            sourceOs << "present.source_active=" << activeSourceW << "x" << activeSourceH
                     << " offset=" << activeSourceX << "," << activeSourceY
                     << " surface=" << mtW << "x" << mtH
                     << " aperture=" << (haveAperture ? "yes" : "no")
                     << " remote=" << width << "x" << height;
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
            HRESULT hr = decoder->ProcessOutput(0, 1, &out, &status);
            if (out.pEvents) out.pEvents->Release();
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) return;
            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                ++outputChanges;
                setOutputType();
                continue;
            }
            checkHr(hr, "decoder ProcessOutput");
            if (out.pSample) {
                ++decoded;
                presentSample(out.pSample);
                out.pSample->Release();
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

        HRESULT hr = decoder->ProcessInput(0, sample.Get(), 0);
        if (hr == MF_E_NOTACCEPTING) {
            ++backpressure;
            drain();
            hr = decoder->ProcessInput(0, sample.Get(), 0);
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
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0), "NOTIFY_END_STREAMING");
        checkHr(decoder->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, 0), "CLEAR_D3D_MANAGER");
        finished = true;
    }
};

HardwareVideoPipeline::HardwareVideoPipeline(
    HWND hwnd, UINT32 width, UINT32 height, UINT32 fps,
    JerisVideoCodec codec, Logger logger)
    : impl_(std::make_unique<Impl>(hwnd, width, height, fps, codec, std::move(logger))) {}

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
uint64_t HardwareVideoPipeline::presented() const { return impl_->presentedFrames; }
uint64_t HardwareVideoPipeline::busyDrops() const { return impl_->droppedBusy; }
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
