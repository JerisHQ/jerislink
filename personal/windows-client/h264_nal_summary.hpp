#pragma once
// H.264 access unit summary for the viewer's diagnostics: NAL types and sizes,
// and for each slice its first_mb_in_slice and slice_type. Only the first
// bytes of each slice header are read. Header-only, no Windows dependencies,
// so h264_nal_summary_test.cpp can test it as a console program.
//
// SliceLogBudget decides which frames get a line: the first frames, every
// keyframe or discontinuity, every slice layout change, otherwise at most one
// line per interval, and never more than a fixed total.

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace jl::h264 {

struct Slice {
    int nalType = 0;
    int firstMb = -1;
    int sliceType = -1;  // slice_type % 5: 0 P, 1 B, 2 I, 3 SP, 4 SI
    size_t bytes = 0;
};

struct FrameSummary {
    std::vector<int> nalTypes;
    std::vector<size_t> nalSizes;
    std::vector<Slice> slices;

    size_t totalBytes() const {
        size_t n = 0;
        for (size_t s : nalSizes) n += s;
        return n;
    }
    bool idr() const {
        for (int t : nalTypes)
            if (t == 5) return true;
        return false;
    }
    static const char* typeLetter(int t) {
        switch (t) {
        case 0: return "P";
        case 1: return "B";
        case 2: return "I";
        case 3: return "SP";
        case 4: return "SI";
        default: return "?";
        }
    }
    std::string frameType() const {
        if (idr()) return "IDR";
        if (slices.empty()) return "none";
        const std::string first = typeLetter(slices.front().sliceType);
        for (const Slice& s : slices)
            if (first != typeLetter(s.sliceType)) return "mixed";
        return first;
    }
    std::string layout() const {
        std::ostringstream os;
        os << "slices=" << slices.size() << " first_mb=";
        for (size_t i = 0; i < slices.size(); ++i) os << (i ? "," : "") << slices[i].firstMb;
        return os.str();
    }
    std::string line() const {
        std::ostringstream os;
        os << "type=" << frameType() << " bytes=" << totalBytes() << " nals=";
        for (size_t i = 0; i < nalTypes.size(); ++i) os << (i ? "," : "") << nalTypes[i] << ":" << nalSizes[i];
        os << " " << layout() << " slice_types=";
        for (size_t i = 0; i < slices.size(); ++i) os << (i ? "," : "") << typeLetter(slices[i].sliceType);
        os << " slice_bytes=";
        for (size_t i = 0; i < slices.size(); ++i) os << (i ? "," : "") << slices[i].bytes;
        return os.str();
    }
};

namespace detail {

// Exp-Golomb reader over an emulation-prevention-stripped buffer.
struct BitReader {
    const std::vector<uint8_t>& b;
    size_t pos = 0;
    bool ok = true;
    int bit() {
        if (pos >= b.size() * 8) {
            ok = false;
            return 0;
        }
        const int v = (b[pos >> 3] >> (7 - (pos & 7))) & 1;
        ++pos;
        return v;
    }
    long ue() {
        int zeros = 0;
        while (bit() == 0) {
            if (!ok || ++zeros > 31) {
                ok = false;
                return -1;
            }
        }
        long rest = 0;
        for (int i = 0; i < zeros; ++i) rest = (rest << 1) | bit();
        if (!ok) return -1;
        return (1L << zeros) - 1 + rest;
    }
};

inline std::vector<uint8_t> unescape(const uint8_t* p, size_t n) {
    std::vector<uint8_t> out;
    out.reserve(n);
    int zeros = 0;
    for (size_t i = 0; i < n; ++i) {
        if (zeros >= 2 && p[i] == 3) {
            zeros = 0;
            continue;
        }
        out.push_back(p[i]);
        zeros = p[i] == 0 ? zeros + 1 : 0;
    }
    return out;
}

inline void addNal(FrameSummary& f, const uint8_t* nal, size_t n) {
    if (n == 0) return;
    const int type = nal[0] & 0x1f;
    f.nalTypes.push_back(type);
    f.nalSizes.push_back(n);
    if (type != 1 && type != 5) return;
    const size_t headLen = n - 1 < 16 ? n - 1 : 16;
    const std::vector<uint8_t> head = unescape(nal + 1, headLen);
    BitReader r{head};
    Slice s;
    s.nalType = type;
    s.bytes = n;
    const long firstMb = r.ue();
    const long sliceType = r.ue();
    s.firstMb = firstMb >= 0 ? static_cast<int>(firstMb) : -1;
    s.sliceType = sliceType >= 0 ? static_cast<int>(sliceType % 5) : -1;
    f.slices.push_back(s);
}

}  // namespace detail

// Start-code (Annex B) NAL units, as the viewer receives them.
inline FrameSummary summarizeAnnexB(const uint8_t* p, size_t n) {
    FrameSummary f;
    size_t i = 0;
    size_t payload = 0;
    bool open = false;
    while (i + 3 <= n) {
        if (p[i] == 0 && p[i + 1] == 0 && p[i + 2] == 1) {
            const size_t code = (i > 0 && p[i - 1] == 0) ? i - 1 : i;
            if (open && code > payload) detail::addNal(f, p + payload, code - payload);
            payload = i + 3;
            open = true;
            i += 3;
        } else {
            ++i;
        }
    }
    if (open && n > payload) detail::addNal(f, p + payload, n - payload);
    return f;
}

inline FrameSummary summarizeAnnexB(const std::vector<uint8_t>& v) {
    return summarizeAnnexB(v.data(), v.size());
}

class SliceLogBudget {
public:
    SliceLogBudget(int initialFrames = 30, double intervalMs = 1000.0, int maxLines = 600)
        : initialFrames_(initialFrames), intervalMs_(intervalMs), maxLines_(maxLines) {}

    // Returns true when this frame gets a line. `layoutChanged` is set when
    // the slice layout differs from the previous frame.
    bool take(const std::string& layout, bool keyFrame, bool discontinuity, double nowMs,
              bool* layoutChanged = nullptr) {
        ++frames_;
        const bool changed = !lastLayout_.empty() && layout != lastLayout_;
        lastLayout_ = layout;
        if (layoutChanged) *layoutChanged = changed;
        const bool due = frames_ <= initialFrames_ || keyFrame || discontinuity || changed ||
                         nowMs - lastLineMs_ >= intervalMs_;
        if (!due || lines_ >= maxLines_) {
            ++suppressed_;
            ++skippedSinceLine_;
            return false;
        }
        ++lines_;
        lastLineMs_ = nowMs;
        lastSkipped_ = skippedSinceLine_;
        skippedSinceLine_ = 0;
        return true;
    }
    // Frames without a line between the previous line and this one.
    uint64_t lastSkipped() const { return lastSkipped_; }
    uint64_t suppressed() const { return suppressed_; }
    int lines() const { return lines_; }

private:
    int initialFrames_;
    double intervalMs_;
    int maxLines_;
    int64_t frames_ = 0;
    int lines_ = 0;
    double lastLineMs_ = -1e300;
    std::string lastLayout_;
    uint64_t suppressed_ = 0;
    uint64_t skippedSinceLine_ = 0;
    uint64_t lastSkipped_ = 0;
};

}  // namespace jl::h264
