package sessionbroker

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	store := newStore(10*time.Minute, bytes.NewReader(bytes.Repeat([]byte{0x42}, 8192)), func() time.Time { return now })

	session, hostToken, err := store.Create("tc-secret-descriptor")
	if err != nil {
		t.Fatal(err)
	}
	if session.State != StateWaiting || session.Code == "" || hostToken == "" {
		t.Fatalf("unexpected create result: %#v hostToken=%q", session, hostToken)
	}

	claim, claimToken, err := store.Claim(session.Code, "Alice", []string{"view", "input"})
	if err != nil {
		t.Fatal(err)
	}
	if claim.State != ClaimPending || claim.TransportDescriptor != "" {
		t.Fatalf("claim=%#v", claim)
	}

	preApprove, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if preApprove.TransportDescriptor != "" {
		t.Fatal("transport descriptor leaked before approval")
	}

	hostView, err := store.Snapshot(session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if hostView.State != StateApprovalPending || hostView.SupporterName != "Alice" || hostView.ClaimID != claim.ID {
		t.Fatalf("host view=%#v", hostView)
	}

	active, err := store.Approve(session.ID, hostToken, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != StateActive || active.Code != "" {
		t.Fatalf("active=%#v", active)
	}

	approved, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if approved.State != ClaimApproved || approved.TransportDescriptor != "tc-secret-descriptor" {
		t.Fatalf("approved=%#v", approved)
	}

	ended, err := store.End(session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if ended.State != StateEnded {
		t.Fatalf("ended=%#v", ended)
	}

	afterEnd, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if afterEnd.State != ClaimEnded || afterEnd.TransportDescriptor != "" {
		t.Fatalf("after end=%#v", afterEnd)
	}
}

func TestReplaceInvalidatesOldCodeAndClaim(t *testing.T) {
	store := NewStore(10 * time.Minute)
	oldSession, hostToken, err := store.Create("old-transport")
	if err != nil {
		t.Fatal(err)
	}
	claim, claimToken, err := store.Claim(oldSession.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}

	newSession, newHostToken, err := store.Replace(oldSession.ID, hostToken, "new-transport")
	if err != nil {
		t.Fatal(err)
	}
	if newSession.ID == oldSession.ID || newSession.Code == oldSession.Code || newHostToken == hostToken {
		t.Fatal("replacement did not rotate session identity")
	}
	if _, _, err := store.Claim(oldSession.Code, "Other", nil); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("old code err=%v", err)
	}
	oldClaim, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if oldClaim.State != ClaimEnded || oldClaim.TransportDescriptor != "" {
		t.Fatalf("old claim=%#v", oldClaim)
	}
}

func TestReplaceRejectsActiveSession(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, hostToken, err := store.Create("transport")
	if err != nil {
		t.Fatal(err)
	}
	claim, _, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(session.ID, hostToken, claim.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Replace(session.ID, hostToken, "replacement"); !errors.Is(err, ErrInvalidState) {
		t.Fatalf("replace active err=%v", err)
	}
}

func TestOnlyOnePendingSupporter(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, _, err := store.Create("transport")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Claim(session.Code, "Alice", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Claim(session.Code, "Second", nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("second claim err=%v", err)
	}
}

func TestRejectReturnsSessionToWaiting(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, hostToken, err := store.Create("transport")
	if err != nil {
		t.Fatal(err)
	}
	claim, claimToken, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := store.Reject(session.ID, hostToken, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.State != StateWaiting || waiting.Code == "" || waiting.ClaimID != "" {
		t.Fatalf("waiting=%#v", waiting)
	}
	rejected, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.State != ClaimRejected || rejected.TransportDescriptor != "" {
		t.Fatalf("rejected=%#v", rejected)
	}
	if _, _, err := store.Claim(waiting.Code, "Other", nil); err != nil {
		t.Fatalf("claim after rejection: %v", err)
	}
}

func TestWaitingTTLExpiresCodeAndClaim(t *testing.T) {
	now := time.Date(2026, 10, 8, 1, 0, 0, 0, time.UTC)
	store := newStore(10*time.Minute, bytes.NewReader(bytes.Repeat([]byte{0x51}, 8192)), func() time.Time { return now })
	session, _, err := store.Create("transport")
	if err != nil {
		t.Fatal(err)
	}
	claim, claimToken, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(11 * time.Minute)
	if _, _, err := store.Claim(session.Code, "Other", nil); !errors.Is(err, ErrCodeNotFound) {
		t.Fatalf("expired code err=%v", err)
	}
	expired, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if expired.State != ClaimExpired || expired.TransportDescriptor != "" {
		t.Fatalf("expired claim=%#v", expired)
	}
}

func TestUnauthorizedTokens(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, _, err := store.Create("transport")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Snapshot(session.ID, "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("host auth err=%v", err)
	}
	claim, _, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ClaimStatus(claim.ID, "wrong"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("claim auth err=%v", err)
	}
}

func TestPendingClaimLeaveReturnsHostToWaiting(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, hostToken, err := store.Create("transport")
	if err != nil {
		t.Fatal(err)
	}
	claim, claimToken, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}

	left, err := store.LeaveClaim(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if left.State != ClaimEnded {
		t.Fatalf("left=%#v", left)
	}

	host, err := store.Snapshot(session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if host.State != StateWaiting || host.ClaimID != "" || host.SupporterName != "" {
		t.Fatalf("host=%#v", host)
	}
	if _, _, err := store.Claim(host.Code, "Other", nil); err != nil {
		t.Fatalf("same waiting code should be claimable again: %v", err)
	}
}

func TestApprovedClaimLeaveEndsSessionAndDestroysTransport(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, hostToken, err := store.Create("transport-secret")
	if err != nil {
		t.Fatal(err)
	}
	claim, claimToken, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(session.ID, hostToken, claim.ID); err != nil {
		t.Fatal(err)
	}

	left, err := store.LeaveClaim(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if left.State != ClaimEnded || left.TransportDescriptor != "" {
		t.Fatalf("left=%#v", left)
	}

	host, err := store.Snapshot(session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if host.State != StateEnded {
		t.Fatalf("host=%#v", host)
	}

	status, err := store.ClaimStatus(claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != ClaimEnded || status.TransportDescriptor != "" {
		t.Fatalf("status=%#v", status)
	}
}

func TestStoreCapacityReleasedAfterEnd(t *testing.T) {
	store := NewStoreWithOptions(StoreOptions{
		WaitingTTL:        10 * time.Minute,
		MaxLiveSessions:   1,
		TerminalRetention: 15 * time.Minute,
	})
	first, token, err := store.Create("transport-one")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create("transport-two"); !errors.Is(err, ErrCapacity) {
		t.Fatalf("second create err=%v, want ErrCapacity", err)
	}
	if _, err := store.End(first.ID, token); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Create("transport-three"); err != nil {
		t.Fatalf("capacity should be released after End: %v", err)
	}
}

func TestTerminalRetentionPrunesSessionAndClaim(t *testing.T) {
	now := time.Date(2026, 10, 8, 5, 0, 0, 0, time.UTC)
	store := newStoreWithOptions(StoreOptions{
		WaitingTTL:        10 * time.Minute,
		MaxLiveSessions:   10,
		TerminalRetention: 5 * time.Minute,
	}, bytes.NewReader(bytes.Repeat([]byte{0x61}, 16384)), func() time.Time { return now })

	session, hostToken, err := store.Create("transport-secret")
	if err != nil {
		t.Fatal(err)
	}
	claim, claimToken, err := store.Claim(session.Code, "Alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Approve(session.ID, hostToken, claim.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.End(session.ID, hostToken); err != nil {
		t.Fatal(err)
	}

	now = now.Add(6 * time.Minute)
	if _, err := store.Snapshot(session.ID, hostToken); !errors.Is(err, ErrNotFound) {
		t.Fatalf("snapshot after retention err=%v, want ErrNotFound", err)
	}
	if _, err := store.ClaimStatus(claim.ID, claimToken); !errors.Is(err, ErrClaimNotFound) {
		t.Fatalf("claim after retention err=%v, want ErrClaimNotFound", err)
	}
}

func TestClaimRejectsUntrustedSupporterNameControls(t *testing.T) {
	badNames := []string{
		"",
		"   ",
		"Alice\nConnected to attacker.",
		"Alice\rConnected to attacker.",
		"Alice\tadmin",
		"Alice\x1b[2J",
		"Alice\u2028Connected to attacker.",
		"Alice\u2029Connected to attacker.",
		"Alice\u202e",
		strings.Repeat("a", 65),
	}
	for _, name := range badNames {
		t.Run(fmt.Sprintf("name-%q", name), func(t *testing.T) {
			store := NewStore(10 * time.Minute)
			session, hostToken, err := store.Create("test-transport")
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.Claim(session.Code, name, []string{"view"}); err == nil {
				t.Fatalf("accepted unsafe supporter name %q", name)
			}
			state, err := store.Snapshot(session.ID, hostToken)
			if err != nil {
				t.Fatal(err)
			}
			if state.State != StateWaiting || state.ClaimID != "" {
				t.Fatalf("invalid claim changed state: %#v", state)
			}
		})
	}
}

func TestClaimAcceptsHumanNamesWithoutControlCharacters(t *testing.T) {
	store := NewStore(10 * time.Minute)
	session, _, err := store.Create("test-transport")
	if err != nil {
		t.Fatal(err)
	}
	claim, _, err := store.Claim(session.Code, "  Alice 陳  ", []string{"view"})
	if err != nil {
		t.Fatal(err)
	}
	if claim.SupporterName != "Alice 陳" {
		t.Fatalf("unexpected supporter name %q", claim.SupporterName)
	}
}
