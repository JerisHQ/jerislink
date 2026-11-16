// File transfer wire codec (file_proto.hpp): every type round-trips, fixed
// sizes are exact, bounds hold, and the byte layout matches the Mac host's
// FileProtocol.swift (same golden bytes as its self-test).
#include "file_proto.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

std::string hex(uint8_t t) {
    char b[8];
    std::snprintf(b, sizeof(b), "0x%02x", unsigned(t));
    return b;
}

}  // namespace

int main() {
    using namespace jl::file;
    const std::vector<Message> all = {
        Hello{1, 0x0005},
        HelloAck{1, 0, kMaxChunk, kMaxTotalBytes},
        Offer{0x01020304, purpose::kPush, 3, 1ull << 40},
        Entry{7, 2, kind::kFile, 12345, -1, {'a', '/', 'b', '.', 't', 'x', 't'}},
        Reply{7, status::kBadPath},
        Data{7, 2, 1ull << 33, std::vector<uint8_t>(kMaxChunk, 0xAB)},
        FileEnd{7, 2, std::vector<uint8_t>(32, 9)},
        Result{7, status::kOk, 3},
        Cancel{7, status::kCancelled},
        Request{7, 2, 0, 4u << 20},
        Progress{7, 99},
        Ping{{1, 2, 3, 4}},
        Reveal{7},
    };
    for (size_t i = 0; i < all.size(); ++i) {
        const Message& m = all[i];
        const uint8_t t = typeOf(m);
        expect(t == 0x50 + i, "type of variant " + std::to_string(i) + " is " + hex(uint8_t(0x50 + i)));
        const auto bytes = encode(m);
        if (!bytes) { expect(false, "encode " + hex(t)); continue; }
        const auto back = decode(t, *bytes);
        expect(back && *back == m, hex(t) + " round trip");
        if (t != type::kData && t != type::kEntry && !bytes->empty()) {
            std::vector<uint8_t> shorter(bytes->begin(), bytes->end() - 1);
            std::vector<uint8_t> longer = *bytes;
            longer.push_back(0);
            expect(!decode(t, shorter) && !decode(t, longer), hex(t) + " one byte short or long is rejected");
        }
    }

    // Golden bytes, identical to the Mac self-test.
    expect(*encode(Hello{1, 0x0102}) == std::vector<uint8_t>{1, 1, 2}, "HELLO caps big-endian");
    expect(*encode(Reply{0x0A0B0C0D, 4}) == std::vector<uint8_t>{0x0A, 0x0B, 0x0C, 0x0D, 4}, "REPLY layout");
    expect(*encode(HelloAck{1, 0, kMaxChunk, kMaxTotalBytes}) ==
               std::vector<uint8_t>{1, 0, 0, 0x80, 0, 0, 0, 0, 0x05, 0, 0, 0, 0},
           "HELLO_ACK layout (chunk 32768, total 20 GiB)");
    expect(*encode(Offer{1, purpose::kSend, 2, 3}) ==
               std::vector<uint8_t>{0, 0, 0, 1, 2, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 3},
           "OFFER layout");

    // Bounds.
    expect(!decode(type::kData, std::vector<uint8_t>(16 + kMaxChunk + 1, 0)), "DATA over 32 KiB rejected");
    expect(!encode(Data{1, 0, 0, std::vector<uint8_t>(kMaxChunk + 1, 0)}), "DATA over 32 KiB not encoded");
    expect(!decode(type::kEntry, std::vector<uint8_t>(25, 0)), "ENTRY with empty path rejected");
    expect(!decode(type::kEntry, std::vector<uint8_t>(25 + kMaxPathBytes + 1, 0)), "ENTRY path over 1024 bytes rejected");
    {
        std::vector<uint8_t> fullPath(25, 0);   // header with kind 0 (file)
        fullPath.insert(fullPath.end(), kMaxPathBytes, 'a');
        expect(decode(type::kEntry, fullPath).has_value(), "ENTRY path of 1024 bytes accepted");
    }
    auto badKind = *encode(Entry{1, 0, 0, 0, 0, {'a'}});
    badKind[8] = 2;
    expect(!decode(type::kEntry, badKind), "ENTRY unknown kind rejected");
    auto badPurpose = *encode(Offer{1, 1, 1, 1});
    badPurpose[4] = 0;
    expect(!decode(type::kOffer, badPurpose), "OFFER purpose 0 rejected");
    badPurpose[4] = 5;
    expect(!decode(type::kOffer, badPurpose), "OFFER purpose 5 rejected");
    expect(!decode(0x4F, {}) && !decode(0x5D, {}) && !decode(0x30, {}), "types outside 0x50-0x5C rejected");
    expect(!encode(FileEnd{1, 0, {1}}), "FILE_END needs a 32-byte hash");
    expect(!encode(Ping{{1, 2, 3}}), "PING needs a 4-byte token");
    expect(kMaxPayload == 16 + 32768, "largest payload is one DATA chunk");
    expect(caps::kViewer == 0, "F1 viewer advertises no file features (caps=0)");

    std::printf("FileProtoTest %d PASS / %d FAIL\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
