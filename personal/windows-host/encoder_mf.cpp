#include "encoder_mf.hpp"

#include "host_protocol.hpp"

#include <windows.h>
#include <codecapi.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <wmcodecdsp.h>

#include <cstdio>
#include <cstring>

namespace jlh {

namespace {

// IID_ICodecAPI, spelled out: MinGW has no __uuidof for it and MSVC keeps it
// in strmiids.lib.
constexpr GUID kIidCodecApi = {0x901db4c7, 0x31ce, 0x41a2, {0x85, 0xdc, 0x8f, 0xa0, 0xbf, 0x41, 0xb8, 0xda}};

template <class T>
void release(T*& p) {
    if (p) { p->Release(); p = nullptr; }
}

std::string hr(const char* what, HRESULT h) {
    char b[96];
    std::snprintf(b, sizeof(b), "%s hr=0x%08lx", what, static_cast<unsigned long>(h));
    return b;
}

HRESULT setU32(ICodecAPI* api, const GUID& key, ULONG v) {
    VARIANT var;
    VariantInit(&var);
    var.vt = VT_UI4;
    var.ulVal = v;
    return api->SetValue(&key, &var);
}

HRESULT setBool(ICodecAPI* api, const GUID& key, bool v) {
    VARIANT var;
    VariantInit(&var);
    var.vt = VT_BOOL;
    var.boolVal = v ? VARIANT_TRUE : VARIANT_FALSE;
    return api->SetValue(&key, &var);
}

// MF_MT_MPEG_SEQUENCE_HEADER of the output type, as Annex B.
std::vector<uint8_t> sequenceHeader(IMFTransform* t) {
    std::vector<uint8_t> out;
    IMFMediaType* type = nullptr;
    if (FAILED(t->GetOutputCurrentType(0, &type))) return out;
    UINT32 size = 0;
    if (SUCCEEDED(type->GetBlobSize(MF_MT_MPEG_SEQUENCE_HEADER, &size)) && size > 0) {
        out.resize(size);
        if (FAILED(type->GetBlob(MF_MT_MPEG_SEQUENCE_HEADER, out.data(), size, nullptr))) out.clear();
    }
    type->Release();
    return out;
}

// How ProcessOutput wants its sample: who allocates it and how big. Read
// after every output type change, since a new type can change both.
HRESULT readOutputStreamInfo(IMFTransform* t, int width, int height, bool& providesSamples, DWORD& bufferBytes) {
    MFT_OUTPUT_STREAM_INFO info{};
    const HRESULT h = t->GetOutputStreamInfo(0, &info);
    if (FAILED(h)) return h;
    providesSamples =
        (info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES)) != 0;
    bufferBytes = info.cbSize ? info.cbSize : DWORD(width) * DWORD(height) * 2;
    return S_OK;
}

}  // namespace

constexpr int kMaxStreamChanges = 2;

struct MfH264Encoder::Impl {
    IMFTransform* mft = nullptr;
    ICodecAPI* api = nullptr;
    bool providesSamples = false;
    DWORD outputBufferBytes = 0;
    std::vector<uint8_t> header;
    int64_t frameDuration = 0;
};

MfH264Encoder::MfH264Encoder() = default;
MfH264Encoder::~MfH264Encoder() { close(); }

bool MfH264Encoder::isOpen() const { return impl_ && impl_->mft; }

void MfH264Encoder::close() {
    if (!impl_) return;
    if (impl_->mft) {
        impl_->mft->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
        impl_->mft->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
    }
    release(impl_->api);
    release(impl_->mft);
    delete impl_;
    impl_ = nullptr;
}

bool MfH264Encoder::open(const EncoderConfig& cfg, std::string& error) {
    close();
    cfg_ = cfg;
    impl_ = new Impl;
    impl_->frameDuration = 10'000'000LL / (cfg.fps > 0 ? cfg.fps : 30);
    HRESULT h = CoCreateInstance(CLSID_CMSH264EncoderMFT, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&impl_->mft));
    if (FAILED(h)) { error = hr("encoder.create", h); close(); return false; }
    h = impl_->mft->QueryInterface(kIidCodecApi, reinterpret_cast<void**>(&impl_->api));
    if (FAILED(h)) { error = hr("encoder.codecapi", h); close(); return false; }

    // Rate control and GOP shape go in before the media types.
    ICodecAPI* api = impl_->api;
    setU32(api, CODECAPI_AVEncCommonRateControlMode, eAVEncCommonRateControlMode_CBR);
    setU32(api, CODECAPI_AVEncCommonMeanBitRate, ULONG(cfg.bitrateMbps) * 1'000'000UL);
    setU32(api, CODECAPI_AVEncMPVDefaultBPictureCount, 0);
    setU32(api, CODECAPI_AVEncMPVGOPSize, ULONG(cfg.gopFrames));
    setBool(api, CODECAPI_AVLowLatencyMode, true);
    setU32(api, CODECAPI_AVEncCommonQualityVsSpeed, 0);  // fastest

    IMFMediaType* out = nullptr;
    h = MFCreateMediaType(&out);
    if (FAILED(h)) { error = hr("encoder.output_type_create", h); close(); return false; }
    out->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    out->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_H264);
    out->SetUINT32(MF_MT_AVG_BITRATE, UINT32(cfg.bitrateMbps) * 1'000'000U);
    out->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    out->SetUINT32(MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_High);
    MFSetAttributeSize(out, MF_MT_FRAME_SIZE, UINT32(cfg.width), UINT32(cfg.height));
    MFSetAttributeRatio(out, MF_MT_FRAME_RATE, UINT32(cfg.fps), 1);
    MFSetAttributeRatio(out, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    out->SetUINT32(MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709);
    out->SetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235);
    out->SetUINT32(MF_MT_VIDEO_PRIMARIES, MFVideoPrimaries_BT709);
    out->SetUINT32(MF_MT_TRANSFER_FUNCTION, MFVideoTransFunc_709);
    h = impl_->mft->SetOutputType(0, out, 0);
    out->Release();
    if (FAILED(h)) { error = hr("encoder.output_type", h); close(); return false; }

    IMFMediaType* in = nullptr;
    h = MFCreateMediaType(&in);
    if (FAILED(h)) { error = hr("encoder.input_type_create", h); close(); return false; }
    in->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    in->SetGUID(MF_MT_SUBTYPE, MFVideoFormat_NV12);
    in->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    MFSetAttributeSize(in, MF_MT_FRAME_SIZE, UINT32(cfg.width), UINT32(cfg.height));
    MFSetAttributeRatio(in, MF_MT_FRAME_RATE, UINT32(cfg.fps), 1);
    MFSetAttributeRatio(in, MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    in->SetUINT32(MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709);
    in->SetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235);
    h = impl_->mft->SetInputType(0, in, 0);
    in->Release();
    if (FAILED(h)) { error = hr("encoder.input_type", h); close(); return false; }

    // Some settings only stick once the types are set; harmless twice.
    setU32(api, CODECAPI_AVEncMPVGOPSize, ULONG(cfg.gopFrames));
    setBool(api, CODECAPI_AVLowLatencyMode, true);

    h = readOutputStreamInfo(impl_->mft, cfg.width, cfg.height, impl_->providesSamples, impl_->outputBufferBytes);
    if (FAILED(h)) { error = hr("encoder.output_info", h); close(); return false; }
    impl_->header = sequenceHeader(impl_->mft);

    impl_->mft->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    impl_->mft->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
    return true;
}

bool MfH264Encoder::encode(const uint8_t* nv12, int64_t ts, bool forceKeyframe, std::vector<uint8_t>& outBytes,
                           bool& keyFrame, std::string& error) {
    outBytes.clear();
    keyFrame = false;
    if (!isOpen()) { error = "encoder.not_open"; return false; }
    if (forceKeyframe) setU32(impl_->api, CODECAPI_AVEncVideoForceKeyFrame, 1);

    const DWORD frameBytes = DWORD(cfg_.width) * DWORD(cfg_.height) * 3 / 2;
    IMFMediaBuffer* buf = nullptr;
    HRESULT h = MFCreateMemoryBuffer(frameBytes, &buf);
    if (FAILED(h)) { error = hr("encoder.in_buffer", h); return false; }
    BYTE* p = nullptr;
    h = buf->Lock(&p, nullptr, nullptr);
    if (FAILED(h)) { buf->Release(); error = hr("encoder.in_lock", h); return false; }
    std::memcpy(p, nv12, frameBytes);
    buf->Unlock();
    buf->SetCurrentLength(frameBytes);
    IMFSample* sample = nullptr;
    h = MFCreateSample(&sample);
    if (SUCCEEDED(h)) h = sample->AddBuffer(buf);
    buf->Release();
    if (FAILED(h)) { release(sample); error = hr("encoder.in_sample", h); return false; }
    sample->SetSampleTime(ts);
    sample->SetSampleDuration(impl_->frameDuration);
    h = impl_->mft->ProcessInput(0, sample, 0);
    sample->Release();
    if (FAILED(h)) { error = hr("encoder.process_input", h); return false; }

    // Every failure below returns false: the caller closes and reopens the
    // encoder rather than retrying a transform in an unknown state.
    int streamChanges = 0;
    for (;;) {
        MFT_OUTPUT_DATA_BUFFER od{};
        IMFSample* outSample = nullptr;
        if (!impl_->providesSamples) {
            IMFMediaBuffer* ob = nullptr;
            h = MFCreateMemoryBuffer(impl_->outputBufferBytes, &ob);
            if (FAILED(h)) { error = hr("encoder.out_buffer", h); return false; }
            h = MFCreateSample(&outSample);
            if (SUCCEEDED(h)) h = outSample->AddBuffer(ob);
            ob->Release();
            if (FAILED(h)) { release(outSample); error = hr("encoder.out_sample", h); return false; }
            od.pSample = outSample;
        }
        DWORD status = 0;
        h = impl_->mft->ProcessOutput(0, 1, &od, &status);
        if (od.pEvents) od.pEvents->Release();
        if (h == MF_E_TRANSFORM_NEED_MORE_INPUT) {
            if (outSample) outSample->Release();
            break;
        }
        if (h == MF_E_TRANSFORM_STREAM_CHANGE) {
            if (outSample) outSample->Release();
            if (od.pSample && od.pSample != outSample) od.pSample->Release();
            // One renegotiation is normal; a transform that keeps asking is broken.
            if (++streamChanges > kMaxStreamChanges) { error = "encoder.stream_change_loop"; return false; }
            IMFMediaType* t = nullptr;
            h = impl_->mft->GetOutputAvailableType(0, 0, &t);
            if (SUCCEEDED(h)) {
                h = impl_->mft->SetOutputType(0, t, 0);
                t->Release();
            }
            if (FAILED(h)) { error = hr("encoder.stream_change", h); return false; }
            h = readOutputStreamInfo(impl_->mft, cfg_.width, cfg_.height, impl_->providesSamples,
                                     impl_->outputBufferBytes);
            if (FAILED(h)) { error = hr("encoder.stream_change_info", h); return false; }
            impl_->header = sequenceHeader(impl_->mft);
            continue;
        }
        if (FAILED(h)) {
            if (outSample) outSample->Release();
            if (od.pSample && od.pSample != outSample) od.pSample->Release();
            error = hr("encoder.process_output", h);
            return false;
        }
        IMFSample* got = od.pSample;
        if (!got) break;  // success without a sample: nothing more this frame
        IMFMediaBuffer* contiguous = nullptr;
        h = got->ConvertToContiguousBuffer(&contiguous);
        if (SUCCEEDED(h)) {
            BYTE* q = nullptr;
            DWORD len = 0;
            h = contiguous->Lock(&q, nullptr, &len);
            if (SUCCEEDED(h)) {
                outBytes.insert(outBytes.end(), q, q + len);
                contiguous->Unlock();
            }
            contiguous->Release();
        }
        got->Release();
        if (FAILED(h)) { error = hr("encoder.out_read", h); return false; }
    }
    if (outBytes.empty()) return true;
    const auto types = annexBNalTypes(outBytes.data(), outBytes.size());
    for (int t : types)
        if (t == 5) keyFrame = true;
    if (keyFrame) ensureParameterSets(outBytes, impl_->header);
    return true;
}

}  // namespace jlh
