#pragma once
// PR-C r4 (Pepper's r3 review, item 2): what a read-only view (--no-control)
// does on its own to get its session back. Such a viewer sends no input, and
// input is what normally asks for a reconnect, re-runs nothing else and
// ends a pause. So, from the session loop (every 250 ms):
//  - When the NoChallenge retries on control ran out (paused), start a new
//    round after a gap (what a fresh key press does in a view with input),
//    backing off up to kResumeMaxGapMs. Never while the attempt is halted
//    (wrong password, replaced...): ControlChannel::keepSession checks that.
// PR-C r5 (Pepper's r4 review, item 3): the video negotiation is no longer
// here. The reconnect worker renegotiates on every new control session
// (ControlChannel::setRenegotiateOnReconnect), off the UI thread, and the
// loop applies each answer (takeRenegotiated).
// PR-C r14 (Pepper's r13 review, item 4): the automatic retries have a
// total budget. Once the session has been down kAutoRetryCapMs (2 min) with
// no round authenticating, the loop stops retrying and the attempt ends
// (Client::autoRetryStopped): only the user connects again.
// Plain arithmetic on a millisecond clock, so it is tested without sockets.
#include <algorithm>

namespace jl::viewer {

class ReadOnlyRecovery {
public:
    static constexpr double kResumeFirstGapMs = 5000;
    static constexpr double kResumeMaxGapMs = 60000;
    static constexpr double kAutoRetryCapMs = 120000;

    // `resumeFirstGapMs`, `autoRetryCapMs`: tests shorten them.
    explicit ReadOnlyRecovery(double resumeFirstGapMs = kResumeFirstGapMs, double autoRetryCapMs = kAutoRetryCapMs)
        : resumeFirstGapMs_(resumeFirstGapMs), autoRetryCapMs_(autoRetryCapMs) {}

    // r14: true once the session has been down (`connectedNow` false) for
    // the whole budget since it was last seen up: the loop stops retrying.
    // Stays true until the session is seen up again.
    bool retryExpired(bool connectedNow, double nowMs) {
        if (connectedNow) {
            downSinceMs_ = -1;
            return false;
        }
        if (downSinceMs_ < 0) downSinceMs_ = nowMs;
        return nowMs - downSinceMs_ >= autoRetryCapMs_;
    }
    // How long the session has been down (0: up).
    double downMs(double nowMs) const { return downSinceMs_ < 0 ? 0 : nowMs - downSinceMs_; }

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
    void sessionBack() {
        resumes_ = 0;
        downSinceMs_ = -1;
    }
    unsigned resumes() const { return resumes_; }
    double resumeGapMs() const {
        return std::min(kResumeMaxGapMs, resumeFirstGapMs_ * double(1u << std::min(resumes_, 4u)));
    }

private:
    double resumeFirstGapMs_;
    double autoRetryCapMs_;
    double downSinceMs_ = -1;
    bool pausedSeen_ = false;
    double nextResumeMs_ = 0;
    unsigned resumes_ = 0;
};

}  // namespace jl::viewer
