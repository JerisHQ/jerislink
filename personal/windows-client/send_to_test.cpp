// Tests for send_to.hpp (F5a Send to JerisLink): --send-to arguments, path
// checks, the viewer's decision, dialog texts, exit codes and the pipe
// request / reply bytes (strict lengths, limits, corrupt input).
#include "send_to.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace jl::sendto;
using jl::filepanel::Host;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

void expectEq(const std::string& got, const std::string& want, const std::string& what) {
    expect(got == want, what + (got == want ? "" : "  got [" + got + "] want [" + want + "]"));
}

void arguments() {
    auto a = parseArgs({L"C:\\Program Files\\JerisLink\\Jerislink.exe"});
    expect(!a.sendTo, "args: plain launch is not Send to");
    a = parseArgs({L"Jerislink.exe", L"--source-ip", L"100.64.0.25"});
    expect(!a.sendTo, "args: viewer options are not Send to");
    a = parseArgs({L"Jerislink.exe", L"--send-to"});
    expect(a.sendTo && a.items.empty(), "args: --send-to with nothing selected");
    a = parseArgs({L"Jerislink.exe", L"--send-to", L"C:\\Users\\me\\a b.txt", L"", L"D:\\Photos"});
    expect(a.sendTo && a.items.size() == 2 && a.items[0] == L"C:\\Users\\me\\a b.txt" && a.items[1] == L"D:\\Photos",
           "args: paths kept as given (spaces), empty ones dropped, folders allowed");
    a = parseArgs({L"Jerislink.exe", L"C:\\x.txt", L"--send-to"});
    expect(!a.sendTo, "args: --send-to only counts as the first argument");
    a = parseArgs({L"Jerislink.exe", L"--send-to", L"C:\\\x4E2D\x6587\\\x5831\x544A.pdf"});
    expect(a.sendTo && a.items.size() == 1 && a.items[0].size() == 12, "args: non-ASCII names stay wide");
    a = parseArgs({L"Jerislink.exe", L"--send-to-too-many"});
    expect(a.sendTo && a.tooMany && a.items.empty(), "args: --send-to-too-many is a Send to run");
    expect(checkArgs(a) == Reply::TooMany, "args: --send-to-too-many answers too many");
    a = parseArgs({L"Jerislink.exe", L"--send-to-too-many", L"C:\\a.txt"});
    expect(a.tooMany && a.items.empty() && checkArgs(a) == Reply::TooMany, "args: --send-to-too-many ignores paths");
    a = parseArgs({L"Jerislink.exe", L"--send-to", L"C:\\a.txt"});
    expect(!a.tooMany && checkArgs(a) == Reply::Started, "args: plain --send-to is not too many");
}

// Store build: the Explorer command's command line (send_to_shell.cpp).
// The real CommandLineToArgvW round trip is in send_to_pipe_test.cpp.
void commandLines() {
    expect(quoteArg(L"C:\\a b.txt") == L"\"C:\\a b.txt\"", "quote: spaces inside quotes");
    expect(quoteArg(L"D:\\") == L"\"D:\\\\\"", "quote: trailing backslash doubled before the closing quote");
    expect(quoteArg(L"\\\\nas\\s") == L"\"\\\\nas\\s\"", "quote: UNC backslashes kept as they are");
    expect(quoteArg(L"a\"b") == L"\"a\\\"b\"", "quote: an inner quote is escaped");
    expect(quoteArg(L"a\\\"b") == L"\"a\\\\\\\"b\"", "quote: backslashes before a quote doubled, plus one");
    expect(quoteArg(L"") == L"\"\"", "quote: empty argument stays an argument");

    const std::wstring exe = L"C:\\Program Files\\WindowsApps\\J\\Jerislink.exe";
    expect(commandLine(exe, {L"C:\\a b.txt", L"D:\\"}) ==
               L"\"C:\\Program Files\\WindowsApps\\J\\Jerislink.exe\" --send-to \"C:\\a b.txt\" \"D:\\\\\"",
           "cmdline: exe, flag, then each item quoted");
    const std::wstring item = L"C:\\" + std::wstring(100, L'x');
    const auto fits = commandLine(exe, std::vector<std::wstring>(300, item));
    expect(fits.size() <= kMaxCommandLineChars && fits.find(L"--send-to-too-many") == std::wstring::npos,
           "cmdline: 300 items of 103 chars fit");
    const auto over = commandLine(exe, std::vector<std::wstring>(400, item));
    expect(over == quoteArg(exe) + L" --send-to-too-many", "cmdline: over 32,766 chars becomes --send-to-too-many");
}

void paths() {
    expect(isAcceptablePath(L"C:\\a.txt"), "path: drive path");
    expect(isAcceptablePath(L"d:/folder"), "path: forward slash, lower-case drive");
    expect(isAcceptablePath(L"\\\\nas\\share\\f.bin"), "path: UNC");
    expect(isAcceptablePath(L"\\\\?\\C:\\very\\long"), "path: long-path form");
    expect(isAcceptablePath(L"\\\\?\\UNC\\nas\\share\\f"), "path: long-path UNC");
    expect(!isAcceptablePath(L"a.txt"), "path: relative refused");
    expect(!isAcceptablePath(L"C:a.txt"), "path: drive-relative refused");
    expect(!isAcceptablePath(L"\\a.txt"), "path: root-relative refused");
    expect(!isAcceptablePath(L"\\\\.\\pipe\\x"), "path: device path refused");
    expect(!isAcceptablePath(L"\\\\?\\GLOBALROOT\\x"), "path: long-path non-drive refused");
    expect(!isAcceptablePath(std::wstring(L"C:\\a\0b", 6)), "path: embedded NUL refused");
    expect(!isAcceptablePath(L"C:\\" + std::wstring(kMaxPathChars, L'a')), "path: longer than 32767 refused");

    expect(checkItems({}) == Reply::NothingSelected, "items: none selected");
    expect(checkItems({L"C:\\a", L"relative"}) == Reply::BadRequest, "items: one bad path refuses all");
    expect(checkItems(std::vector<std::wstring>(kMaxItems, L"C:\\a")) == Reply::Started, "items: 1,000 is fine");
    expect(checkItems(std::vector<std::wstring>(kMaxItems + 1, L"C:\\a")) == Reply::TooMany, "items: 1,001 is too many");
}

void decisions() {
    expect(decide(false, Host::Full, false, true) == Reply::NotConnected, "decide: no Mac session");
    expect(decide(true, Host::Full, true, true) == Reply::Busy, "decide: transfer running");
    expect(decide(true, Host::Unknown, false, false) == Reply::Connecting, "decide: Mac caps not known yet");
    expect(decide(true, Host::PasteOnly, false, false) == Reply::HostOld, "decide: F3 host (no reveal)");
    expect(decide(true, Host::None, false, false) == Reply::HostOld, "decide: old host");
    expect(decide(true, Host::Full, false, false) == Reply::HostOld, "decide: upload channel not ready");
    expect(decide(true, Host::Full, false, true) == Reply::Started, "decide: F4 host takes it like a drop");
}

void texts() {
    expectEq(message(Reply::Started), "", "text: no dialog when sending");
    expectEq(message(Reply::NotConnected), "JerisLink is not connected. Connect to your Mac first, then try again.",
             "text: not connected (design 3c)");
    expectEq(message(Reply::Busy), "A transfer is already running. Cancel it in Files, or wait, then try again.",
             "text: busy");
    expectEq(message(Reply::HostOld), "The Mac's JerisLink can't receive files yet. Update JerisLink on the Mac.",
             "text: old host");
    expectEq(message(Reply::TooMany), "Too many items. Send at most 1,000 at a time.", "text: too many");
    for (int i = 0; i <= kReplyMax; ++i) {
        const auto r = static_cast<Reply>(i);
        expect(r == Reply::Started || !message(r).empty(), std::string("text: every refusal has a message ") + name(r));
    }
    expect(exitCode(Reply::Started) == 0, "exit: 0 when started");
    expect(exitCode(Reply::NotConnected) == 21, "exit: 21 not connected");
    expect(exitCode(Reply::NothingSelected) == 27, "exit: 27 nothing selected");
    expect(exitCode(Reply::TooMany) == 28, "exit: 28 too many");
    expect(pipeName(L"S-1-5-21-1-2-3-1001", 2) == L"\\\\.\\pipe\\JerisLink.SendTo.S-1-5-21-1-2-3-1001.2",
           "pipe: name per user SID and session");
}

void wire() {
    const std::vector<std::wstring> items = {L"C:\\a.txt", L"\\\\nas\\s\\\x00E9t\x00E9", L"D:\\folder"};
    const auto b = encodeRequest(items);
    std::vector<std::wstring> out;
    expect(decodeRequest(b.data(), b.size(), out) && out == items, "wire: request round trip");
    expect(b.size() == 4 + 4 + (4 + 8 * 2) + (4 + 11 * 2) + (4 + 9 * 2), "wire: exact request size");
    expect(b[0] == 'J' && b[1] == 'L' && b[2] == 'S' && b[3] == '1' && b[4] == 3 && b[5] == 0 && b[8] == 8 &&
               b[12] == 'C' && b[13] == 0,
           "wire: magic, little-endian count and length, UTF-16LE");

    auto cut = b;
    cut.pop_back();
    expect(!decodeRequest(cut.data(), cut.size(), out) && out.empty(), "wire: truncated request refused");
    auto extra = b;
    extra.push_back(0);
    expect(!decodeRequest(extra.data(), extra.size(), out), "wire: trailing byte refused");
    auto magic = b;
    magic[3] = '2';
    expect(!decodeRequest(magic.data(), magic.size(), out), "wire: wrong magic refused");
    auto zero = encodeRequest({});
    expect(!decodeRequest(zero.data(), zero.size(), out), "wire: zero items refused");
    auto many = encodeRequest(std::vector<std::wstring>(kMaxItems + 1, L"C:\\a"));
    expect(!decodeRequest(many.data(), many.size(), out), "wire: more than 1,000 items refused");
    auto bad = encodeRequest({L"C:\\ok", L"relative.txt"});
    expect(!decodeRequest(bad.data(), bad.size(), out) && out.empty(), "wire: relative path refused, nothing kept");
    auto huge = b;
    huge[8] = 0xFF; huge[9] = 0xFF; huge[10] = 0xFF; huge[11] = 0x7F;  // length 2^31
    expect(!decodeRequest(huge.data(), huge.size(), out), "wire: absurd length refused without allocating");
    expect(!decodeRequest(nullptr, 0, out), "wire: empty input refused");
    std::vector<uint8_t> big(kMaxRequestBytes + 1, 0);
    expect(!decodeRequest(big.data(), big.size(), out), "wire: request over 4 MiB refused");

    for (int i = 0; i <= kReplyMax; ++i) {
        const auto e = encodeReply(static_cast<Reply>(i));
        Reply r = Reply::Failed;
        expect(e.size() == 5 && decodeReply(e.data(), e.size(), r) && r == static_cast<Reply>(i),
               std::string("wire: reply round trip ") + name(static_cast<Reply>(i)));
    }
    auto e = encodeReply(Reply::Busy);
    e[4] = kReplyMax + 1;
    Reply r = Reply::Started;
    expect(!decodeReply(e.data(), e.size(), r) && r == Reply::Started, "wire: unknown reply code refused");
    e = encodeReply(Reply::Busy);
    e.push_back(0);
    expect(!decodeReply(e.data(), e.size(), r), "wire: long reply refused");
}

}  // namespace

int main() {
    arguments();
    commandLines();
    paths();
    decisions();
    texts();
    wire();
    std::printf("send to: %d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
