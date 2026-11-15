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
    {
        // Golden SPS bytes shared with the Mac host self-test (independent bit
        // writer): display size after cropping.
        struct Golden { const char* name; Bytes nal; int w; int h; };
        const Golden golden[] = {
            {"high 3840x2160 L5.2", {0x67, 0x64, 0x00, 0x34, 0xac, 0xda, 0x00, 0xf0, 0x01, 0x0f, 0x90}, 3840, 2160},
            {"constrained high 1920x1080 crop 4", {0x67, 0x64, 0x0c, 0x2a, 0xac, 0xda, 0x01, 0xe0, 0x08, 0x9f, 0x95}, 1920, 1080},
            {"high 3392x1904 L5.1", {0x67, 0x64, 0x00, 0x33, 0xac, 0xda, 0x00, 0xd4, 0x03, 0xbe, 0x40}, 3392, 1904},
            {"main 1920x1080 poc type 1", {0x67, 0x4d, 0x00, 0x28, 0xd1, 0x99, 0xa2, 0xa0, 0x1e, 0x00, 0x89, 0xf9, 0x50}, 1920, 1080},
            {"high 1280x720 scaling list", {0x67, 0x64, 0x00, 0x1f, 0xad, 0x84, 0x3f, 0xff, 0x80, 0xda, 0x01, 0x40, 0x16, 0xe4}, 1280, 720},
            {"baseline 16x16", {0x67, 0x42, 0x00, 0x00, 0xed, 0x3c, 0x80}, 16, 16},
        };
        for (const Golden& g : golden) {
            int w = 0, h = 0;
            const bool ok = detail::parseSpsDisplaySize(g.nal.data(), g.nal.size(), &w, &h);
            expect(ok && w == g.w && h == g.h,
                   std::string("sps size: ") + g.name + " -> " + std::to_string(w) + "x" + std::to_string(h));
        }
        Bytes au;
        append(au, golden[0].nal, true);
        append(au, pps, false);
        append(au, idr0, true);
        const FrameSummary f = summarizeAnnexB(au);
        expect(f.spsWidth == 3840 && f.spsHeight == 2160, "IDR access unit carries SPS size 3840x2160");
        expect(f.line().find("sps") == std::string::npos, "SPS size does not change the slice line");
        int w = 0, h = 0;
        expect(!detail::parseSpsDisplaySize(pps.data(), pps.size(), &w, &h), "sps size: a PPS is rejected");
        expect(!detail::parseSpsDisplaySize(sps.data(), sps.size(), &w, &h), "sps size: a truncated SPS is rejected");
        Bytes pOnly;
        append(pOnly, p0, false);
        expect(summarizeAnnexB(pOnly).spsWidth == 0, "P access unit has no SPS size");
    }
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
