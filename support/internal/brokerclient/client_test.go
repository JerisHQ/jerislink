package brokerclient_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/JerisHQ/jerislink/support/internal/brokerclient"
	"github.com/JerisHQ/jerislink/support/internal/sessionbroker"
)

func TestClientLifecycle(t *testing.T) {
	ts := httptest.NewServer(sessionbroker.NewHTTPHandler(sessionbroker.NewStore(10 * time.Minute)))
	defer ts.Close()

	client, err := brokerclient.New(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := client.Create(ctx, "tc-secret")
	if err != nil {
		t.Fatal(err)
	}
	if session.ID == "" || session.Code == "" || session.HostToken == "" || session.State != "waiting" {
		t.Fatalf("create=%#v", session)
	}
	hostToken := session.HostToken

	view, err := client.Snapshot(ctx, session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if view.State != "waiting" {
		t.Fatalf("snapshot=%#v", view)
	}

	replaced, err := client.Replace(ctx, session.ID, hostToken, "tc-secret-2")
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ID == session.ID || replaced.Code == session.Code || replaced.HostToken == hostToken {
		t.Fatalf("replace=%#v", replaced)
	}

	ended, err := client.End(ctx, replaced.ID, replaced.HostToken)
	if err != nil {
		t.Fatal(err)
	}
	if ended.State != "ended" {
		t.Fatalf("end=%#v", ended)
	}
}

func TestClientRejectsNonLoopbackPlainHTTP(t *testing.T) {
	if _, err := brokerclient.New("http://broker.example.test"); err == nil {
		t.Fatal("expected insecure remote HTTP rejection")
	}
	if _, err := brokerclient.New("https://broker.example.test"); err != nil {
		t.Fatalf("HTTPS should be accepted: %v", err)
	}
}

func TestSupporterClaimApproveAndLeaveLifecycle(t *testing.T) {
	store := sessionbroker.NewStore(10 * time.Minute)
	ts := httptest.NewServer(sessionbroker.NewHTTPHandler(store))
	defer ts.Close()

	client, err := brokerclient.New(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	session, err := client.Create(ctx, "tc-supporter-secret")
	if err != nil {
		t.Fatal(err)
	}
	hostToken := session.HostToken

	claim, err := client.Claim(ctx, session.Code, "Alice", []string{"view", "input", "clipboard"})
	if err != nil {
		t.Fatal(err)
	}
	if claim.State != "pending" || claim.ClaimToken == "" || claim.TransportDescriptor != "" {
		t.Fatalf("claim=%#v", claim)
	}
	claimToken := claim.ClaimToken

	host, err := client.Snapshot(ctx, session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if host.State != "approval_pending" || host.ClaimID != claim.ID {
		t.Fatalf("host=%#v", host)
	}
	if _, err := client.Approve(ctx, session.ID, hostToken, claim.ID); err != nil {
		t.Fatal(err)
	}

	approved, err := client.ClaimStatus(ctx, claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if approved.State != "approved" || approved.TransportDescriptor != "tc-supporter-secret" {
		t.Fatalf("approved=%#v", approved)
	}

	left, err := client.LeaveClaim(ctx, claim.ID, claimToken)
	if err != nil {
		t.Fatal(err)
	}
	if left.State != "ended" || left.TransportDescriptor != "" {
		t.Fatalf("left=%#v", left)
	}
	host, err = client.Snapshot(ctx, session.ID, hostToken)
	if err != nil {
		t.Fatal(err)
	}
	if host.State != "ended" {
		t.Fatalf("host after leave=%#v", host)
	}
}
