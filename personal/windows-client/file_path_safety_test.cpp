// Received-path rules (file_path_safety.hpp): nothing a sender writes can
// leave the destination folder or name a Windows device, NFD becomes NFC,
// and clash names follow Explorer ("name (2).ext").
#include "file_path_safety.hpp"

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

using jl::file::path::Rejection;

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }
Rejection why(const std::string& s) { return jl::file::path::validate(bytes(s)).why; }
bool ok(const std::string& s) { return why(s) == Rejection::None; }

}  // namespace

int main() {
    using jl::file::path::clashName;
    using jl::file::path::validate;

    expect(ok("report.pdf") && ok("Photos/2026/IMG 0001.HEIC") && ok("~$draft.docx") && ok(".profile"),
           "ordinary relative names accepted");
    {
        const auto v = validate(bytes("dir/sub/file.txt"));
        expect(v.ok() && v.wide == L"dir\\sub\\file.txt" && v.utf8 == "dir/sub/file.txt",
               "accepted path is joined with backslashes for Windows");
    }

    // Leaving the folder.
    expect(why("") == Rejection::Empty, "empty rejected");
    expect(why("/etc/passwd") == Rejection::Absolute, "absolute rejected");
    expect(why("..") == Rejection::DotComponent && why("../x") == Rejection::DotComponent &&
               why("a/../../x") == Rejection::DotComponent && why("a/./b") == Rejection::DotComponent,
           "'.' and '..' components rejected");
    expect(why("../\xcc\xb8x") == Rejection::DotComponent && why("a/\xcc\x81/../b") == Rejection::DotComponent,
           "combining mark after '/' does not hide '..'");
    expect(why("a\\..\\b") == Rejection::Backslash && why("\\\\server\\share") == Rejection::Backslash,
           "backslash and UNC rejected");
    expect(why("C:") == Rejection::DriveLetter && why("c:/Windows") == Rejection::DriveLetter &&
               why("Z:file") == Rejection::DriveLetter,
           "drive letter rejected");
    expect(why("a//b") == Rejection::EmptyComponent && why("a/") == Rejection::EmptyComponent,
           "empty component rejected");

    // Bytes.
    expect(why(std::string("a\0b", 3)) == Rejection::ControlChar && why("a\nb") == Rejection::ControlChar &&
               why("a\x7f") == Rejection::ControlChar,
           "NUL and control chars rejected");
    expect(why("a\xff" "b") == Rejection::NotUtf8, "invalid UTF-8 rejected");
    expect(why("a\xc0\xaf") == Rejection::NotUtf8, "overlong UTF-8 '/' rejected");
    expect(why("a\xed\xa0\x80") == Rejection::NotUtf8, "UTF-8 surrogate rejected");
    expect(why("a\xf4\x90\x80\x80") == Rejection::NotUtf8, "code point above U+10FFFF rejected");

    // Windows-only rules.
    expect(why("ab:c.txt") == Rejection::ReservedChar && why("a*b") == Rejection::ReservedChar &&
               why("what?.txt") == Rejection::ReservedChar && why("\"q\"") == Rejection::ReservedChar &&
               why("a<b>c") == Rejection::ReservedChar && why("a|b") == Rejection::ReservedChar,
           "reserved characters : * ? \" < > | rejected");
    expect(why("CON") == Rejection::ReservedName && why("con.txt") == Rejection::ReservedName &&
               why("dir/Nul.log") == Rejection::ReservedName && why("aux") == Rejection::ReservedName &&
               why("PRN.tar.gz") == Rejection::ReservedName && why("COM1") == Rejection::ReservedName &&
               why("lpt9.txt") == Rejection::ReservedName && why("NUL .txt") == Rejection::ReservedName &&
               why("COM\xc2\xb9") == Rejection::ReservedName,
           "device names rejected with any case and extension");
    expect(ok("CONSOLE.txt") && ok("com10") && ok("COM0") && ok("nul2") && ok("auxiliary"),
           "names that only start like a device accepted");
    expect(why("name.") == Rejection::TrailingDotOrSpace && why("name ") == Rejection::TrailingDotOrSpace &&
               why("dir./x") == Rejection::TrailingDotOrSpace && why("...") == Rejection::TrailingDotOrSpace,
           "trailing dot or space rejected");

    // Limits.
    const std::string c255(255, 'a');
    expect(ok(c255) && why(c255 + "a") == Rejection::ComponentTooLong, "component limit 255 bytes");
    std::string deep32 = "d";
    for (int i = 1; i < 32; ++i) deep32 += "/d";
    expect(ok(deep32) && why(deep32 + "/d") == Rejection::TooDeep, "depth limit 32");
    std::string longPath(200, 'x');
    for (int i = 1; i < 6; ++i) longPath += "/" + std::string(200, 'x');
    expect(why(longPath) == Rejection::PathTooLong, "total limit 1024 bytes");

    // NFC: NFD "Cafe" + U+0301 becomes "Caf" + U+00E9.
    {
        const auto v = validate(bytes("Cafe\xcc\x81.txt"));
        expect(v.ok() && v.utf8 == "Caf\xc3\xa9.txt" && v.wide == L"Caf\u00e9.txt", "NFD normalised to NFC");
    }
    // Rejected verdicts carry no path.
    {
        const auto v = validate(bytes("../x"));
        expect(!v.ok() && v.utf8.empty() && v.wide.empty(), "rejected verdict carries no path");
    }

    // Clash names.
    expect(clashName("report.pdf", 2) == "report (2).pdf", "clash: report (2).pdf");
    expect(clashName("notes", 3) == "notes (3)", "clash: no extension");
    expect(clashName(".profile", 2) == ".profile (2)", "clash: dotfile keeps its name");
    expect(clashName("a.tar.gz", 2) == "a.tar (2).gz", "clash: last dot is the extension");
    {
        std::string longName;
        for (int i = 0; i < 126; ++i) longName += "\xc3\xa9";   // 252 bytes
        longName += ".txt";
        const std::string named = clashName(longName, 10);
        const bool tailOk = named.size() >= 9 && named.compare(named.size() - 9, 9, " (10).txt") == 0;
        expect(named.size() <= 255 && tailOk && jl::file::path::validUtf8(named),
               "clash: shortened to 255 bytes on a code point boundary");
    }

    std::printf("FilePathTest %d PASS / %d FAIL\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
