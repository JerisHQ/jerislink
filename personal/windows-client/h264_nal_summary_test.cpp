// Console test for h264_nal_summary.hpp: slice header fields from golden NAL
// bytes, Annex B splitting, multi-slice frames, and the log budget.
#include "h264_nal_summary.hpp"

#include <cstdio>
#include <string>
#include <vector>

static int gPass = 0, gFail = 0;
static void expect(bool ok, const std::string& what) {
    if (ok) ++gPass; else ++gFail;
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what.c_str());
}

using Bytes = std::vector<uint8_t>;

static void append(Bytes& out, const Bytes& nal, bool fourByteCode) {
    if (fourByteCode) out.push_back(0);
    out.push_back(0);
    out.push_back(0);
    out.push_back(1);
    out.insert(out.end(), nal.begin(), nal.end());
}

int main() {
    using namespace jl::h264;
    const Bytes sps{0x67, 0x64, 0x00, 0x33, 0xac};
    const Bytes pps{0x68, 0xee, 0x3c, 0x80};
    const Bytes idr0{0x65, 0x88, 0xc0, 0x11, 0x22};          // first_mb 0, I
    const Bytes idr4080{0x65, 0x00, 0x1f, 0xe2, 0x23, 0x44}; // first_mb 4080, I
    const Bytes p0{0x41, 0x9b, 0x10};                        // first_mb 0, P
    const Bytes p25440{0x41, 0x00, 0x03, 0x1b, 0x0f};        // first_mb 25440, P

    {
        Bytes au;
        append(au, sps, true);
        append(au, pps, false);
        append(au, idr0, true);
        append(au, idr4080, false);
        const FrameSummary f = summarizeAnnexB(au);
        expect(f.nalTypes == std::vector<int>({7, 8, 5, 5}), "IDR access unit: NAL types 7,8,5,5");
        expect(f.nalSizes == std::vector<size_t>({5, 4, 5, 6}), "IDR access unit: NAL sizes without start codes");
        expect(f.slices.size() == 2, "IDR access unit: two slices");
        expect(f.slices.size() == 2 && f.slices[0].firstMb == 0 && f.slices[1].firstMb == 4080,
               "IDR access unit: first_mb 0 and 4080");
        expect(f.slices.size() == 2 && f.slices[0].sliceType == 2 && f.slices[1].sliceType == 2,
               "IDR access unit: both slices I");
        expect(f.idr() && f.frameType() == "IDR", "IDR access unit: frame type IDR");
        expect(f.layout() == "slices=2 first_mb=0,4080", "IDR access unit: layout " + f.layout());
        expect(f.totalBytes() == 20, "IDR access unit: total bytes 20");
        expect(f.line() == "type=IDR bytes=20 nals=7:5,8:4,5:5,5:6 slices=2 first_mb=0,4080 slice_types=I,I slice_bytes=5,6",
               "IDR access unit: line " + f.line());
    }
    {
        Bytes au;
        append(au, p0, false);
        append(au, p25440, true);
        const FrameSummary f = summarizeAnnexB(au);
        expect(f.frameType() == "P", "P access unit: frame type P");
        expect(f.layout() == "slices=2 first_mb=0,25440", "P access unit: layout " + f.layout());
    }
    {
        Bytes au;
        append(au, idr0, false);
        append(au, p0, false);
        expect(summarizeAnnexB(au).frameType() == "IDR", "IDR with a P slice still reports IDR");
        Bytes mixed;
        append(mixed, Bytes{0x41, 0x88, 0xc0}, false);  // non-IDR I slice
        append(mixed, p0, false);
        expect(summarizeAnnexB(mixed).frameType() == "mixed", "I and P slices in one frame: mixed");
    }
    {
        const Bytes esc{0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x03, 0x00};
        expect(detail::unescape(esc.data(), esc.size()) == Bytes({0x00, 0x00, 0x01, 0x00, 0x00, 0x00}),
               "emulation prevention bytes removed");
        // first_mb 1 coded as 010 followed by escaped zeros: header still parses.
        Bytes au;
        append(au, Bytes{0x41, 0x40, 0x00, 0x00, 0x03, 0x01}, false);
        const FrameSummary f = summarizeAnnexB(au);
        expect(f.slices.size() == 1 && f.slices[0].firstMb == 1, "first_mb parsed before escaped bytes");
    }
    {
        Bytes au;
        append(au, Bytes{0x41, 0x00, 0x00}, false);  // header runs out of bits
        const FrameSummary f = summarizeAnnexB(au);
        expect(f.slices.size() == 1 && f.slices[0].firstMb == -1, "truncated slice header: first_mb -1");
        expect(summarizeAnnexB(Bytes{}).nalTypes.empty(), "empty buffer: no NALs");
        expect(summarizeAnnexB(Bytes{0x65, 0x88}).nalTypes.empty(), "no start code: no NALs");
    }
    {
        SliceLogBudget b(2, 1000.0, 4);
        const std::string a = "slices=1 first_mb=0", two = "slices=2 first_mb=0,4080";
        bool changed = false;
        expect(b.take(a, true, false, 0, &changed), "budget: frame 1 logged (initial)");
        expect(b.take(a, false, false, 10, &changed), "budget: frame 2 logged (initial)");
        expect(!b.take(a, false, false, 20, &changed), "budget: frame 3 skipped (inside interval)");
        expect(b.take(two, false, false, 30, &changed) && changed && b.lastSkipped() == 1,
               "budget: layout change logged with skipped=1");
        expect(b.take(two, true, false, 40, &changed), "budget: keyframe logged");
        expect(!b.take(two, true, false, 5000, &changed), "budget: max lines reached");
        expect(b.lines() == 4 && b.suppressed() == 2, "budget: 4 lines, 2 suppressed");
        SliceLogBudget c(0, 1000.0, 100);
        expect(c.take(a, false, false, 0) && !c.take(a, false, false, 500) && c.take(a, false, false, 1000) &&
                   c.take(a, false, true, 1001),
               "budget: once per interval, discontinuity always");
    }
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
