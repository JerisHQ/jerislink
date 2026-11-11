#include "video_decoder_factory.hpp"

#include <mfapi.h>
#include <mfidl.h>
#include <wmcodecdsp.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <stdexcept>
#include <vector>

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

bool isD3D11Aware(IMFTransform* transform) {
    if (!transform) return false;
    ComPtr<IMFAttributes> attrs;
    if (FAILED(transform->GetAttributes(&attrs)) || !attrs) return false;
    UINT32 aware = FALSE;
    return SUCCEEDED(attrs->GetUINT32(MF_SA_D3D11_AWARE, &aware)) && aware;
}

} // namespace

JerisVideoCodec jerisVideoCodecFromString(const std::string& value) {
    std::string lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower == "h264" || lower == "avc") return JerisVideoCodec::H264;
    if (lower == "hevc" || lower == "h265") return JerisVideoCodec::HEVC;
    throw std::invalid_argument("unsupported codec: " + value);
}

const char* jerisVideoCodecName(JerisVideoCodec codec) {
    return codec == JerisVideoCodec::HEVC ? "hevc" : "h264";
}

GUID jerisVideoCodecInputSubtype(JerisVideoCodec codec) {
    return codec == JerisVideoCodec::HEVC ? MFVideoFormat_HEVC_ES : MFVideoFormat_H264_ES;
}

ComPtr<IMFTransform> createJerisMfDecoder(
    JerisVideoCodec codec,
    bool requireD3D11Aware,
    std::string* friendlyName) {
    if (codec == JerisVideoCodec::H264) {
        ComPtr<IMFTransform> decoder;
        checkHr(CoCreateInstance(CLSID_CMSH264DecoderMFT, nullptr, CLSCTX_INPROC_SERVER,
                                 IID_PPV_ARGS(&decoder)), "CoCreate H264 decoder");
        if (requireD3D11Aware && !isD3D11Aware(decoder.Get())) {
            throw std::runtime_error("Media Foundation H.264 decoder is not D3D11-aware");
        }
        if (friendlyName) *friendlyName = "CMSH264DecoderMFT";
        return decoder;
    }

    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video, MFVideoFormat_HEVC_ES};
    MFT_REGISTER_TYPE_INFO output{MFMediaType_Video, MFVideoFormat_NV12};
    IMFActivate** activates = nullptr;
    UINT32 count = 0;
    checkHr(MFTEnumEx(MFT_CATEGORY_VIDEO_DECODER,
                      MFT_ENUM_FLAG_ALL | MFT_ENUM_FLAG_SORTANDFILTER,
                      &input, &output, &activates, &count),
            "MFTEnumEx HEVC decoder");

    ComPtr<IMFTransform> selected;
    std::string selectedName;
    for (UINT32 i = 0; i < count; ++i) {
        wchar_t* name = nullptr;
        UINT32 nameLength = 0;
        if (SUCCEEDED(activates[i]->GetAllocatedString(MFT_FRIENDLY_NAME_Attribute,
                                                        &name, &nameLength)) && name) {
            selectedName = wideToUtf8(name);
            CoTaskMemFree(name);
        }

        ComPtr<IMFTransform> candidate;
        HRESULT activateHr = activates[i]->ActivateObject(IID_PPV_ARGS(&candidate));
        if (SUCCEEDED(activateHr) && candidate &&
            (!requireD3D11Aware || isD3D11Aware(candidate.Get()))) {
            selected = candidate;
            break;
        }
        selectedName.clear();
    }

    for (UINT32 i = 0; i < count; ++i) {
        if (activates[i]) activates[i]->Release();
    }
    CoTaskMemFree(activates);

    if (!selected) {
        throw std::runtime_error(requireD3D11Aware
            ? "no D3D11-aware Media Foundation HEVC decoder found"
            : "no Media Foundation HEVC decoder found");
    }
    if (friendlyName) *friendlyName = selectedName.empty() ? "HEVC decoder" : selectedName;
    return selected;
}

bool jerisVideoCodecSupported(JerisVideoCodec codec, bool requireD3D11Aware) {
    try {
        auto decoder = createJerisMfDecoder(codec, requireD3D11Aware, nullptr);
        return decoder != nullptr;
    } catch (...) {
        return false;
    }
}
