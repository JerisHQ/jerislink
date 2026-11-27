#include "capture.hpp"

#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <thread>

namespace jlh {

namespace {

template <class T>
void release(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

std::string hr(const char* what, HRESULT h) {
    char b[96];
    std::snprintf(b, sizeof(b), "%s hr=0x%08lx", what, static_cast<unsigned long>(h));
    return b;
}

HRESULT makeStaging(ID3D11Device* device, UINT w, UINT h, ID3D11Texture2D** out) {
    D3D11_TEXTURE2D_DESC sd{};
    sd.Width = w;
    sd.Height = h;
    sd.MipLevels = 1;
    sd.ArraySize = 1;
    sd.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    sd.SampleDesc.Count = 1;
    sd.Usage = D3D11_USAGE_STAGING;
    sd.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    return device->CreateTexture2D(&sd, nullptr, out);
}

std::string narrow(const wchar_t* w) {
    std::string s;
    for (; *w; ++w) s.push_back(*w < 128 ? char(*w) : '?');
    return s;
}

}  // namespace

struct ScreenCapture::Impl {
    CaptureMode backend = CaptureMode::Auto;  // Auto = none open
    std::string description;
    // DDA
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* ctx = nullptr;
    IDXGIOutputDuplication* dup = nullptr;
    ID3D11Texture2D* staging = nullptr;
    bool frameHeld = false;
    bool mapped = false;
    int w = 0, h = 0;
    // GDI
    HDC screenDc = nullptr, memDc = nullptr;
    HBITMAP bitmap = nullptr;
    HGDIOBJ previousBitmap = nullptr;  // memDc's own bitmap, put back before DeleteObject
    void* bits = nullptr;
};

ScreenCapture::ScreenCapture() = default;
ScreenCapture::~ScreenCapture() { close(); }

const char* ScreenCapture::backend() const {
    if (!impl_) return "none";
    return impl_->backend == CaptureMode::Dda ? "dda" : impl_->backend == CaptureMode::Gdi ? "gdi" : "none";
}

std::string ScreenCapture::describe() const { return impl_ ? impl_->description : std::string(); }

void ScreenCapture::close() {
    if (!impl_) return;
    if (impl_->mapped) impl_->ctx->Unmap(impl_->staging, 0);
    if (impl_->frameHeld) impl_->dup->ReleaseFrame();
    release(impl_->staging);
    release(impl_->dup);
    release(impl_->ctx);
    release(impl_->device);
    if (impl_->previousBitmap) SelectObject(impl_->memDc, impl_->previousBitmap);
    if (impl_->bitmap) DeleteObject(impl_->bitmap);
    if (impl_->memDc) DeleteDC(impl_->memDc);
    if (impl_->screenDc) ReleaseDC(nullptr, impl_->screenDc);
    delete impl_;
    impl_ = nullptr;
}


bool ScreenCapture::open(CaptureMode mode, std::string& error) {
    close();
    impl_ = new Impl;
    std::string ddaError;
    if (mode == CaptureMode::Auto && !ddaUnusable_.empty()) ddaError = "dda.disabled " + ddaUnusable_;
    else if (mode != CaptureMode::Gdi) {
        IDXGIFactory1* factory = nullptr;
        HRESULT h = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
        if (FAILED(h)) ddaError = hr("dda.factory", h);
        IDXGIAdapter1* adapter = nullptr;
        IDXGIOutput* output = nullptr;
        for (UINT a = 0; factory && !output && factory->EnumAdapters1(a, &adapter) != DXGI_ERROR_NOT_FOUND; ++a) {
            if (adapter->EnumOutputs(0, &output) == DXGI_ERROR_NOT_FOUND) {
                output = nullptr;
                release(adapter);
            }
        }
        release(factory);
        if (!output && ddaError.empty()) ddaError = "dda.no_output";
        if (output) {
            DXGI_ADAPTER_DESC1 ad{};
            adapter->GetDesc1(&ad);
            DXGI_OUTPUT_DESC od{};
            output->GetDesc(&od);
            impl_->description = "adapter=\"" + narrow(ad.Description) + "\" output=\"" + narrow(od.DeviceName) + "\"";
            const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0};
            h = D3D11CreateDevice(adapter, D3D_DRIVER_TYPE_UNKNOWN, nullptr, D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels,
                                  UINT(std::size(levels)), D3D11_SDK_VERSION, &impl_->device, nullptr, &impl_->ctx);
            IDXGIOutput1* out1 = nullptr;
            if (FAILED(h)) ddaError = hr("dda.device", h);
            else if (FAILED(h = output->QueryInterface(IID_PPV_ARGS(&out1)))) ddaError = hr("dda.output1", h);
            else if (FAILED(h = out1->DuplicateOutput(impl_->device, &impl_->dup))) ddaError = hr("dda.duplicate", h);
            release(out1);
            release(output);
            release(adapter);
            DXGI_OUTDUPL_DESC dd{};
            if (impl_->dup) impl_->dup->GetDesc(&dd);
            // DDA hands back the unrotated scan-out image. H1 does not rotate
            // it: a rotated screen goes to GDI (Auto) or fails (Dda).
            if (impl_->dup && dd.Rotation != DXGI_MODE_ROTATION_IDENTITY &&
                dd.Rotation != DXGI_MODE_ROTATION_UNSPECIFIED) {
                ddaError = "dda.rotated rotation=" + std::to_string(int(dd.Rotation));
                release(impl_->dup);
            }
            // Staging is made here so a device that cannot make one sends Auto
            // to GDI; acquire() remakes it if a frame comes back another size.
            if (impl_->dup && FAILED(h = makeStaging(impl_->device, dd.ModeDesc.Width, dd.ModeDesc.Height,
                                                     &impl_->staging))) {
                ddaError = hr("dda.staging", h);
                release(impl_->dup);
            }
            if (impl_->dup) {
                impl_->w = int(dd.ModeDesc.Width);
                impl_->h = int(dd.ModeDesc.Height);
                impl_->backend = CaptureMode::Dda;
                return true;
            }
        }
        release(impl_->ctx);
        release(impl_->device);
        if (mode == CaptureMode::Dda) {
            error = ddaError;
            close();
            return false;
        }
    }
    // GDI fallback: the primary screen.
    impl_->w = GetSystemMetrics(SM_CXSCREEN);
    impl_->h = GetSystemMetrics(SM_CYSCREEN);
    impl_->screenDc = GetDC(nullptr);
    impl_->memDc = impl_->screenDc ? CreateCompatibleDC(impl_->screenDc) : nullptr;
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = impl_->w;
    bi.bmiHeader.biHeight = -impl_->h;  // top-down
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 32;
    bi.bmiHeader.biCompression = BI_RGB;
    if (impl_->memDc && impl_->w > 0 && impl_->h > 0)
        impl_->bitmap = CreateDIBSection(impl_->memDc, &bi, DIB_RGB_COLORS, &impl_->bits, nullptr, 0);
    if (!impl_->bitmap) {
        error = (ddaError.empty() ? std::string() : ddaError + "; ") + "gdi.open failed";
        close();
        return false;
    }
    impl_->previousBitmap = SelectObject(impl_->memDc, impl_->bitmap);
    if (!impl_->previousBitmap || impl_->previousBitmap == HGDI_ERROR) {
        impl_->previousBitmap = nullptr;
        error = (ddaError.empty() ? std::string() : ddaError + "; ") + "gdi.select failed";
        close();
        return false;
    }
    impl_->description = (ddaError.empty() ? std::string() : "dda_unavailable=\"" + ddaError + "\" ") + "gdi primary";
    impl_->backend = CaptureMode::Gdi;
    return true;
}

int ScreenCapture::acquire(int timeoutMs, CapturedFrame& out, std::string& error) {
    if (!impl_) { error = "capture.not_open"; return -1; }
    Impl& m = *impl_;
    if (m.backend == CaptureMode::Gdi) {
        // GDI has no change signal: every call is a new frame; the caller paces.
        (void)timeoutMs;
        if (GetSystemMetrics(SM_CXSCREEN) != m.w || GetSystemMetrics(SM_CYSCREEN) != m.h) {
            error = "gdi.size_changed";
            return -1;
        }
        if (!BitBlt(m.memDc, 0, 0, m.w, m.h, m.screenDc, 0, 0, SRCCOPY | CAPTUREBLT)) {
            error = "gdi.bitblt failed err=" + std::to_string(GetLastError());
            return -1;
        }
        GdiFlush();
        out.bgra = static_cast<const uint8_t*>(m.bits);
        out.width = m.w;
        out.height = m.h;
        out.stride = size_t(m.w) * 4;
        return 1;
    }
    if (m.mapped) { m.ctx->Unmap(m.staging, 0); m.mapped = false; }
    if (m.frameHeld) { m.dup->ReleaseFrame(); m.frameHeld = false; }
    DXGI_OUTDUPL_FRAME_INFO fi{};
    IDXGIResource* res = nullptr;
    HRESULT h = m.dup->AcquireNextFrame(UINT(timeoutMs), &fi, &res);
    if (h == DXGI_ERROR_WAIT_TIMEOUT) return 0;
    if (FAILED(h)) { error = hr("dda.acquire", h); return -1; }
    m.frameHeld = true;
    if (fi.LastPresentTime.QuadPart == 0) {  // pointer-only update: no new pixels
        release(res);
        return 0;
    }
    ID3D11Texture2D* tex = nullptr;
    h = res->QueryInterface(IID_PPV_ARGS(&tex));
    release(res);
    if (FAILED(h)) { error = hr("dda.texture", h); return -1; }
    // CopyResource needs identical shapes: size the staging texture from
    // the frame DDA actually returned, not from the mode description.
    D3D11_TEXTURE2D_DESC td{};
    tex->GetDesc(&td);
    // These two would fail the same way after a reopen: mark DDA unusable
    // so Auto moves to GDI instead of reopening DDA forever.
    if (td.Format != DXGI_FORMAT_B8G8R8A8_UNORM) {
        error = ddaUnusable_ = "dda.format " + std::to_string(int(td.Format));
        release(tex);
        return -1;
    }
    if (int(td.Width) != m.w || int(td.Height) != m.h) {
        release(m.staging);
        h = makeStaging(m.device, td.Width, td.Height, &m.staging);
        if (FAILED(h)) {
            error = ddaUnusable_ = hr("dda.staging", h);
            release(tex);
            return -1;
        }
        m.w = int(td.Width);
        m.h = int(td.Height);
    }
    m.ctx->CopyResource(m.staging, tex);
    release(tex);
    D3D11_MAPPED_SUBRESOURCE map{};
    h = m.ctx->Map(m.staging, 0, D3D11_MAP_READ, 0, &map);
    if (FAILED(h)) { error = hr("dda.map", h); return -1; }
    m.mapped = true;
    out.bgra = static_cast<const uint8_t*>(map.pData);
    out.width = m.w;
    out.height = m.h;
    out.stride = map.RowPitch;
    return 1;
}

}  // namespace jlh
