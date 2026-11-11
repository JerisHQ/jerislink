#pragma once

#include <guiddef.h>
#include <mftransform.h>
#include <wrl/client.h>

#include <string>

enum class JerisVideoCodec {
    H264,
    HEVC,
};

JerisVideoCodec jerisVideoCodecFromString(const std::string& value);
const char* jerisVideoCodecName(JerisVideoCodec codec);
GUID jerisVideoCodecInputSubtype(JerisVideoCodec codec);
Microsoft::WRL::ComPtr<IMFTransform> createJerisMfDecoder(
    JerisVideoCodec codec,
    bool requireD3D11Aware,
    std::string* friendlyName = nullptr);
bool jerisVideoCodecSupported(JerisVideoCodec codec, bool requireD3D11Aware = false);
