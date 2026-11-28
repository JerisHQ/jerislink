// JerisLink Windows host, H3: the connection settings that are not tied to
// the registry (design D7, D8, D9).
//
// - How the stored values read and write (blacklist and failure rows, the
//   secret's plain bytes before DPAPI), so a malformed value is refused
//   the same way everywhere.
// - The settings window's checks and Chinese messages, as the macOS host's
//   ConnectionSettings.swift words them.
// - Where to listen (tailnet or loopback, as ListenEndpoint.swift).
// - PolicyHolder: the password and the whitelist the host serves under, and
//   what happens when they change while it runs (every connection void, no
//   notice; the Mac restarts its control service instead).
//
// Portable: host_config_win.hpp does the registry and DPAPI, auth_test runs
// the rest on Linux too.
#pragma once

#include "host_auth_conn.hpp"

#include <cerrno>
#include <cinttypes>
#include <cstdlib>

namespace jlh::settings {

using auth::AuthSecret;
using auth::BlockedEntry;
using auth::Bytes;
using auth::FailureRecord;
using auth::StoreStamp;

// ----------------------------------------------------------- stored rows

// One blacklist row: "ip<TAB>unix seconds<TAB>reason". The reason has no
// tab or line break and at most 64 bytes.
inline std::string formatBlocked(const BlockedEntry& e) {
    std::string reason = e.reason.substr(0, 64);
    for (char& c : reason)
        if (c == '\t' || c == '\n' || c == '\r' || c == '\0') c = ' ';
    return e.ip + "\t" + std::to_string(e.at) + "\t" + reason;
}

inline bool parseInt64(const std::string& s, int64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    size_t i = s[0] == '-' ? 1 : 0;
    if (i == s.size()) return false;
    for (size_t j = i; j < s.size(); ++j)
        if (s[j] < '0' || s[j] > '9') return false;
    errno = 0;
    char* end = nullptr;
    const long long v = std::strtoll(s.c_str(), &end, 10);
    if (errno || !end || *end) return false;
    out = int64_t(v);
    return true;
}

inline std::vector<std::string> splitTabs(const std::string& s) {
    std::vector<std::string> out(1);
    for (char c : s) {
        if (c == '\t') out.emplace_back();
        else out.back().push_back(c);
    }
    return out;
}

// nullopt: not a row this host wrote (the caller decides what that means).
inline std::optional<BlockedEntry> parseBlocked(const std::string& row) {
    const auto f = splitTabs(row);
    if (f.size() != 3 || !auth::isIpv4(f[0])) return std::nullopt;
    BlockedEntry e;
    e.ip = f[0];
    if (!parseInt64(f[1], e.at)) return std::nullopt;
    e.reason = f[2];
    return e;
}

// One failure row: "unix seconds<TAB>ip<TAB>reason<TAB>failures".
inline std::string formatRecord(const FailureRecord& r) {
    std::string reason = r.reason.substr(0, 40);
    for (char& c : reason)
        if (c == '\t' || c == '\n' || c == '\r' || c == '\0') c = ' ';
    return std::to_string(r.at) + "\t" + r.ip + "\t" + reason + "\t" + std::to_string(r.failures);
}
inline std::optional<FailureRecord> parseRecord(const std::string& row) {
    const auto f = splitTabs(row);
    if (f.size() != 4 || !auth::isIpv4(f[1])) return std::nullopt;
    FailureRecord r;
    int64_t n = 0;
    if (!parseInt64(f[0], r.at) || !parseInt64(f[3], n) || n < 0 || n > 1000000) return std::nullopt;
    r.ip = f[1];
    r.reason = f[2];
    r.failures = int(n);
    return r;
}

// The failure times: int64 little-endian, back to back.
inline Bytes encodeTimes(const std::vector<int64_t>& t) {
    Bytes out;
    out.reserve(t.size() * 8);
    for (int64_t v : t)
        for (int i = 0; i < 8; ++i) out.push_back(uint8_t(uint64_t(v) >> (8 * i)));
    return out;
}
inline std::vector<int64_t> decodeTimes(const Bytes& b) {
    std::vector<int64_t> out;
    if (b.size() % 8) return out;
    for (size_t o = 0; o < b.size(); o += 8) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= uint64_t(b[o + size_t(i)]) << (8 * i);
        out.push_back(int64_t(v));
    }
    return out;
}

// ---------------------------------------------------------- the secret

// What DPAPI protects: the whole password state in one value, so one
// registry write changes it (no salt from one password with K from
// another after a crash). Design D7 lists salt, iterations and host id
// with the other settings; they live here with K instead.
//   "JLK1" | iterations BE32 | salt 16 | host id 16 | K 32   (72 bytes)
constexpr uint8_t kSecretMagic[4] = {'J', 'L', 'K', '1'};
constexpr size_t kSecretPlainBytes = 4 + 4 + auth::kSaltBytes + auth::kHostIdBytes + auth::kKeyBytes;
// The viewer takes 100,000 to 10,000,000 (conn_auth.hpp); the host writes
// kIterations.
constexpr uint32_t kMinIterations = 100000, kMaxIterations = 10000000;

inline Bytes encodeSecret(const AuthSecret& s) {
    Bytes out(kSecretMagic, kSecretMagic + 4);
    for (int i = 3; i >= 0; --i) out.push_back(uint8_t(s.iterations >> (8 * i)));
    out.insert(out.end(), s.salt.begin(), s.salt.end());
    out.insert(out.end(), s.hostId.begin(), s.hostId.end());
    out.insert(out.end(), s.key.begin(), s.key.end());
    return out;
}
inline std::shared_ptr<const AuthSecret> decodeSecret(const Bytes& b) {
    if (b.size() != kSecretPlainBytes || std::memcmp(b.data(), kSecretMagic, 4) != 0) return nullptr;
    auto s = std::make_shared<AuthSecret>();
    size_t o = 4;
    s->iterations = (uint32_t(b[o]) << 24) | (uint32_t(b[o + 1]) << 16) | (uint32_t(b[o + 2]) << 8) | uint32_t(b[o + 3]);
    o += 4;
    if (s->iterations < kMinIterations || s->iterations > kMaxIterations) return nullptr;
    std::memcpy(s->salt.data(), b.data() + o, s->salt.size());
    o += s->salt.size();
    std::memcpy(s->hostId.data(), b.data() + o, s->hostId.size());
    o += s->hostId.size();
    std::memcpy(s->key.data(), b.data() + o, s->key.size());
    return s;
}
inline bool sameSecret(const std::shared_ptr<const AuthSecret>& a, const std::shared_ptr<const AuthSecret>& b) {
    if (!a || !b) return !a && !b;
    return a->key == b->key && a->salt == b->salt && a->iterations == b->iterations && a->hostId == b->hostId;
}

// ------------------------------------------------- the window's messages

// A settings change: done (ok) or refused, with the line the window shows.
struct Outcome {
    bool ok = false;
    std::string text;
};
inline Outcome done(std::string t) { return {true, std::move(t)}; }
inline Outcome refused(std::string t) { return {false, std::move(t)}; }

inline const std::string kNotTailnet = "唔係 tailnet IPv4 地址（要喺 100.64.0.0/10 範圍內）：";
inline const std::string kBusy = "另一個連線設定正在儲存，請稍後再試。";

inline std::string passwordProblemsText(const std::vector<auth::PasswordProblem>& ps) {
    std::string out;
    for (auto p : ps) {
        if (!out.empty()) out += "；";
        switch (p) {
        case auth::PasswordProblem::TooShort: out += "最少 " + std::to_string(auth::kMinPasswordLength) + " 個字"; break;
        case auth::PasswordProblem::NoUpper: out += "要有大楷字母 (A-Z)"; break;
        case auth::PasswordProblem::NoLower: out += "要有細楷字母 (a-z)"; break;
        case auth::PasswordProblem::NoSymbol: out += "要有符號（唔係字母、數字或空格）"; break;
        }
    }
    return out;
}

// The checks before a password is derived (ConnectionSettings.setPassword).
// `same`: the two fields match; `nfc`: the password's NFC code points.
inline std::optional<Outcome> passwordRefusal(bool same, const std::u32string& nfc) {
    if (!same) return refused("兩次輸入嘅密碼唔一樣。");
    const auto problems = auth::passwordProblems(nfc);
    if (!problems.empty()) return refused("密碼唔夠強：" + passwordProblemsText(problems));
    return std::nullopt;
}
inline Outcome passwordSaved(bool hadPassword) {
    return done(hadPassword ? "已更改連線密碼；已記住密碼嘅 viewer 要重新輸入。" : "已設定連線密碼。");
}

// A typed list of tailnet addresses, as ConnectionSettings.parseIPs: split
// on line breaks, commas, spaces and tabs; anything that is not a tailnet
// IPv4 is refused, listed in the order typed.
struct TailnetList {
    std::vector<std::string> ips;      // deduplicated, in order
    std::vector<std::string> invalid;  // in order, as typed
};
inline TailnetList parseTailnetList(const std::string& text) {
    TailnetList out;
    std::string cur;
    auto flush = [&] {
        if (cur.empty()) return;
        if (!auth::isTailnetIpv4(cur)) out.invalid.push_back(cur);
        else if (std::find(out.ips.begin(), out.ips.end(), cur) == out.ips.end()) out.ips.push_back(cur);
        cur.clear();
    };
    for (char ch : text) {
        if (ch == '\n' || ch == '\r' || ch == ',' || ch == ' ' || ch == '\t') flush();
        else cur.push_back(ch);
    }
    flush();
    return out;
}
inline std::string joined(const std::vector<std::string>& v, const char* sep) {
    std::string out;
    for (const auto& s : v) {
        if (!out.empty()) out += sep;
        out += s;
    }
    return out;
}
inline Outcome whitelistSaved(size_t n) {
    return done(n == 0 ? "白名單已清空：任何 IP 都要輸入密碼。" : "白名單已儲存（" + std::to_string(n) + " 個 IP）。");
}

inline std::string trimmed(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// How a block's reason reads in the window.
inline std::string reasonText(const std::string& reason) {
    if (reason == "manual") return "人手加入";
    const std::string suffix = " wrong passwords";
    if (reason.size() > suffix.size() && reason.compare(reason.size() - suffix.size(), suffix.size(), suffix) == 0) {
        int64_t n = 0;
        if (parseInt64(reason.substr(0, reason.size() - suffix.size()), n)) return "錯密碼 " + std::to_string(n) + " 次";
    }
    return reason;
}
inline std::string failureReasonText(const std::string& reason) {
    if (reason == "wrong_password") return "密碼錯";
    if (reason == "timeout") return "逾時冇回應";
    if (reason == "bad_response") return "回應格式錯";
    if (reason == "bad_header") return "開頭格式錯";
    return reason;
}
// 「最近 24 小時錯 N 次；最後一個 IP：ip（time）。」 `time`: the last
// failure's local time, already formatted (empty: none).
inline std::string failureSummaryText(const auth::FailureSummary& s, const std::string& time) {
    std::string out = std::string("最近 24 小時錯") + (s.capped ? "至少" : "") + " " + std::to_string(s.last24h) + " 次";
    if (s.lastIp.empty()) return out + "。";
    out += "；最後一個 IP：" + s.lastIp;
    if (!time.empty()) out += "（" + time + "）";
    return out + "。";
}

// ------------------------------------------------------- where to listen

// The macOS host's ports (design D11): control and the other channels on
// TCP 38400, MRM1 on UDP 38412, both on the bind address only.
constexpr uint16_t kControlPort = 38400, kMrm1Port = 38412;

// ListenEndpoint.swift's two modes. Tailnet: the BindIP value when set
// (it must be a tailnet address and up on this PC), else the lowest
// tailnet IPv4 on this PC; never another interface. Loopback: 127.0.0.1
// (local tests).
struct ListenPlan {
    enum Kind { Ready, NotConfigured, Waiting } kind = NotConfigured;
    std::string mode;    // "tailnet" or "loopback"
    std::string bindIp;  // Ready
    std::string why;     // NotConfigured / Waiting
};
inline ListenPlan resolveListen(const std::string& mode, const std::string& bindIp,
                                const std::vector<std::string>& localIpv4) {
    ListenPlan p;
    p.mode = mode.empty() ? "tailnet" : mode;
    if (p.mode == "loopback") {
        p.kind = ListenPlan::Ready;
        p.bindIp = "127.0.0.1";
        return p;
    }
    if (p.mode != "tailnet") {
        p.why = "ListenMode \"" + mode + "\" is not tailnet or loopback";
        return p;
    }
    if (!bindIp.empty()) {
        if (!auth::isTailnetIpv4(bindIp)) {
            p.why = "BindIP " + bindIp + " is not a tailnet address (100.64.0.0/10)";
            return p;
        }
        if (std::find(localIpv4.begin(), localIpv4.end(), bindIp) == localIpv4.end()) {
            p.kind = ListenPlan::Waiting;
            p.why = "tailnet address " + bindIp + " is not up";
            return p;
        }
        p.kind = ListenPlan::Ready;
        p.bindIp = bindIp;
        return p;
    }
    std::vector<uint32_t> tailnet;
    for (const auto& ip : localIpv4)
        if (auth::isTailnetIpv4(ip)) tailnet.push_back(*auth::parseIpv4(ip));
    if (tailnet.empty()) {
        p.kind = ListenPlan::Waiting;
        p.why = "no tailnet address on this PC (Tailscale not connected)";
        return p;
    }
    std::sort(tailnet.begin(), tailnet.end());
    p.kind = ListenPlan::Ready;
    p.bindIp = auth::ipv4String(tailnet.front());
    return p;
}

// ----------------------------------------------------------- PolicyHolder

// What the store says the host serves under.
struct PolicyValues {
    std::shared_ptr<const AuthSecret> secret;  // nullptr: none, or `problem`
    std::vector<std::string> whitelist;
    std::string problem;  // non-empty: the settings did not read; nobody gets in
};

// A stamp of everything a policy depends on (two registry keys on
// Windows). Equal stamps: nothing was written in between.
struct PolicyStamp {
    StoreStamp settings, secret;
    bool operator==(const PolicyStamp&) const = default;
};

class PolicySource {
public:
    virtual ~PolicySource() = default;
    // Cheap; nullopt when it could not be taken (the policy is read again).
    virtual std::optional<PolicyStamp> probe() = 0;
    virtual PolicyValues load() = 0;
};

// The password and whitelist in force. `refresh` is asked before every
// message and send (cheap while nothing changed: one stamp), `tick` by the
// watcher on a registry change and once a second. A change of password or
// whitelist voids every connection (closed, no notice) and moves the
// broker's policy generation, so an AUTH that ran under the old one is
// refused at admit; reconnecting viewers authenticate afresh.
//
// Lock order: this holder, then the broker, then the guard (the broker and
// the guard never call back in here).
class PolicyHolder {
public:
    using LogFn = std::function<void(const std::string&)>;

    PolicyHolder(PolicySource& src, auth::AuthGuard& guard, auth::SessionBroker& broker, LogFn log)
        : src_(src), guard_(guard), broker_(broker), log_(std::move(log)) {}

    // The first read, before anything listens.
    void load() {
        std::lock_guard<std::mutex> g(m_);
        known_ = src_.probe();
        cur_ = src_.load();
        if (!cur_.problem.empty()) cur_.secret.reset();
        guard_.setWhitelist(cur_.whitelist);
        if (!cur_.problem.empty())
            log("auth.policy_unreadable reason=" + cur_.problem + " (nobody is admitted until it reads)");
        else
            log(std::string("auth.policy password=") + (cur_.secret ? "set" : "unset") +
                " whitelist=" + std::to_string(cur_.whitelist.size()) + " source=registry");
    }

    auth::PolicySnapshot snapshot() {
        std::lock_guard<std::mutex> g(m_);
        auth::PolicySnapshot s{cur_.secret, broker_.policyGeneration()};
        if (!cur_.problem.empty()) s.noSecretReason = "settings_unreadable";
        return s;
    }

    bool passwordSet() {
        std::lock_guard<std::mutex> g(m_);
        return cur_.secret != nullptr;
    }

    // r8: the stamp is taken before the read, so a write that lands during
    // it is read again next time.
    void refresh(bool force = false) {
        std::lock_guard<std::mutex> g(m_);
        const auto stamp = src_.probe();
        if (!force && stamp && known_ && *stamp == *known_) return;
        PolicyValues v = src_.load();
        known_ = stamp;
        if (!v.problem.empty()) v.secret.reset();
        const bool secretChanged = !sameSecret(cur_.secret, v.secret);
        const bool whitelistChanged = cur_.whitelist != v.whitelist;
        const bool problemChanged = cur_.problem != v.problem;
        if (!secretChanged && !whitelistChanged && !problemChanged) return;
        const char* password = !secretChanged ? "same" : !cur_.secret ? "set" : !v.secret ? "cleared" : "changed";
        cur_ = std::move(v);
        guard_.setWhitelist(cur_.whitelist);
        if (!cur_.problem.empty())
            log("auth.policy_unreadable reason=" + cur_.problem + " found=running (nobody is admitted until it reads)");
        else
            log(std::string("auth.policy_changed password=") + password + " whitelist=" +
                std::to_string(cur_.whitelist.size()) + " source=registry; every connection closed");
        broker_.voidAll(auth::CloseReason::Policy, true);
    }

    // The watcher's turn: settings read again when they moved, the
    // blacklist and journal read again, newly blocked addresses kicked,
    // and every connection closed when the journal lockdown starts.
    void tick() {
        refresh(false);
        guard_.probeJournal();
        auth::kickNewlyBlocked(guard_, broker_);
        const bool locked = guard_.lockdownReason().has_value();
        bool start = false;
        {
            std::lock_guard<std::mutex> g(m_);
            start = locked && !lockdown_;
            lockdown_ = locked;
        }
        if (start) broker_.voidAll(auth::CloseReason::Lockdown, false);
    }

private:
    void log(const std::string& s) {
        if (log_) log_(s);
    }

    std::mutex m_;
    PolicySource& src_;
    auth::AuthGuard& guard_;
    auth::SessionBroker& broker_;
    LogFn log_;
    std::optional<PolicyStamp> known_;
    PolicyValues cur_;
    bool lockdown_ = false;
};

}  // namespace jlh::settings
