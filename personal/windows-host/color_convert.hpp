// JerisLink Windows host, H1: BGRA desktop pixels to NV12 on the CPU.
//
// BT.709, limited range (Y 16..235, CbCr 16..240): what the viewer's
// decoder path assumes (hardware_video_pipeline.cpp sets YCbCr_Matrix=1 and
// takes the nominal range from the stream, default 16_235). The MF encoder
// input type says the same, so the SPS VUI matches the pixels.
//
// When the destination is smaller than the source (the software encoder is
// capped at 1920x1080) pixels are point-sampled. The hardware path (later
// phases) scales on the GPU instead.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace jlh {

// Even sizes, as NV12 needs; never larger than the source; fits in maxW x maxH
// keeping the aspect ratio.
inline void fitEven(int srcW, int srcH, int maxW, int maxH, int& outW, int& outH) {
    double s = 1.0;
    if (srcW > maxW) s = double(maxW) / srcW;
    if (srcH * s > maxH) s = double(maxH) / srcH;
    outW = int(srcW * s) & ~1;
    outH = int(srcH * s) & ~1;
    if (outW < 2) outW = 2;
    if (outH < 2) outH = 2;
}

// dst: dstW*dstH luma bytes followed by dstW*dstH/2 interleaved CbCr bytes.
inline void bgraToNv12(const uint8_t* src, int srcW, int srcH, size_t srcStride, uint8_t* dst, int dstW, int dstH) {
    std::vector<int> xs(static_cast<size_t>(dstW)), ys(static_cast<size_t>(dstH));
    for (int x = 0; x < dstW; ++x) xs[size_t(x)] = int(int64_t(x) * srcW / dstW);
    for (int y = 0; y < dstH; ++y) ys[size_t(y)] = int(int64_t(y) * srcH / dstH);
    uint8_t* yPlane = dst;
    uint8_t* uv = dst + size_t(dstW) * dstH;
    for (int y = 0; y < dstH; y += 2) {
        const uint8_t* r0 = src + size_t(ys[size_t(y)]) * srcStride;
        const uint8_t* r1 = src + size_t(ys[size_t(y + 1)]) * srcStride;
        uint8_t* y0 = yPlane + size_t(y) * dstW;
        uint8_t* y1 = y0 + dstW;
        uint8_t* c = uv + size_t(y / 2) * dstW;
        for (int x = 0; x < dstW; x += 2) {
            const uint8_t* px[4] = {r0 + 4 * xs[size_t(x)], r0 + 4 * xs[size_t(x + 1)], r1 + 4 * xs[size_t(x)],
                                    r1 + 4 * xs[size_t(x + 1)]};
            int sr = 0, sg = 0, sb = 0;
            for (int k = 0; k < 4; ++k) {
                const int b = px[k][0], g = px[k][1], r = px[k][2];
                // Y = 16 + 0.1826 R + 0.6142 G + 0.0620 B (x1024, rounded)
                const int yy = 16 + ((187 * r + 629 * g + 63 * b + 512) >> 10);
                (k < 2 ? y0 : y1)[x + (k & 1)] = uint8_t(yy);
                sr += r; sg += g; sb += b;
            }
            // Cb = 128 - 0.1006 R - 0.3386 G + 0.4392 B; Cr = 128 + 0.4392 R - 0.3989 G - 0.0403 B
            // on the 2x2 average (sums of four, so >> 12).
            const int cb = 128 + ((-103 * sr - 347 * sg + 450 * sb + 2048) >> 12);
            const int cr = 128 + ((450 * sr - 409 * sg - 41 * sb + 2048) >> 12);
            c[x] = uint8_t(cb < 16 ? 16 : cb > 240 ? 240 : cb);
            c[x + 1] = uint8_t(cr < 16 ? 16 : cr > 240 ? 240 : cr);
        }
    }
}

}  // namespace jlh
