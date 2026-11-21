#pragma once
// PR-C r4 (Pepper's r3 review, item 2): what a read-only view (--no-control)
// does on its own to get its session back. Such a viewer sends no input, and
// input is what normally asks for a reconnect, re-runs nothing else and
// ends a pause. So, from the session loop (every 250 ms):
//  - When the start-up video negotiation never succeeded (the control
//    connection was not up yet), negotiate as soon as a background reconnect
//    has brought the connection back, then start what the answer allows
//    (audio; the keep-alive PING runs in a read-only view from the start,
//    udp_plan.hpp). Tried again with backoff while it fails.
//  - When the NoChallenge retries on control ran out (paused), start a new
//    round after a gap (what a fresh key press does in a view with input),
//    backing off up to kResumeMaxGapMs. Never while the attempt is halted
//    (wrong password, replaced...): ControlChannel::keepSession checks that.
// Plain arithmetic on a millisecond clock, so it is tested without sockets.
#include <algorithm>

namespace jl::viewer {

class ReadOnlyRecovery {
public:
    static constexpr double kNegotiateFirstGapMs = 1000;
    static constexpr double kNegotiateMaxGapMs = 8000;
    static constexpr double kResumeFirstGapMs = 5000;
    static constexpr double kResumeMaxGapMs = 60000;

    // `resumeFirstGapMs`: tests shorten it.
    explicit ReadOnlyRecovery(bool negotiatedAtStart, double resumeFirstGapMs = kResumeFirstGapMs)
        : negotiated_(negotiatedAtStart), resumeFirstGapMs_(resumeFirstGapMs) {}

    bool negotiated() const { return negotiated_; }

    // True when the loop should negotiate the video configuration now.
    bool wantNegotiate(bool controlConnected, double nowMs) const {
        return !negotiated_ && controlConnected && nowMs >= nextNegotiateMs_;
    }
    void negotiateFailed(double nowMs) {
        nextNegotiateMs_ = nowMs + std::min(kNegotiateMaxGapMs, kNegotiateFirstGapMs * double(1u << std::min(negotiateFailures_, 3u)));
        ++negotiateFailures_;
    }
    void negotiateOk() { negotiated_ = true; }
    unsigned negotiateFailures() const { return negotiateFailures_; }

    // Paused (NoChallenge retries spent): true when the loop should end the
    // pause now. The first time it sees the pause it only schedules.
    bool wantResume(bool pausedNow, double nowMs) {
        if (!pausedNow) {
            pausedSeen_ = false;
            return false;
        }
        if (!pausedSeen_) {
            pausedSeen_ = true;
            nextResumeMs_ = nowMs + resumeGapMs();
            return false;
        }
        if (nowMs < nextResumeMs_) return false;
        ++resumes_;
        pausedSeen_ = false;  // the next pause schedules again, with a longer gap
        return true;
    }
    // A round after a resume authenticated: the gap starts small again.
    void sessionBack() { resumes_ = 0; }
    unsigned resumes() const { return resumes_; }
    double resumeGapMs() const {
        return std::min(kResumeMaxGapMs, resumeFirstGapMs_ * double(1u << std::min(resumes_, 4u)));
    }

private:
    bool negotiated_;
    double resumeFirstGapMs_;
    double nextNegotiateMs_ = 0;
    unsigned negotiateFailures_ = 0;
    bool pausedSeen_ = false;
    double nextResumeMs_ = 0;
    unsigned resumes_ = 0;
};

}  // namespace jl::viewer
