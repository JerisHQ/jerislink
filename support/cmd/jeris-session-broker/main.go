package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/JerisHQ/jerislink/support/internal/sessionbroker"
)

func main() {
	defaults := sessionbroker.DefaultHTTPOptions()
	listen := flag.String("listen", "127.0.0.1:8781", "HTTP listen address; keep loopback-only until public broker hardening is complete")
	waitingTTL := flag.Duration("waiting-ttl", 10*time.Minute, "support-code waiting TTL")
	clientIPHeader := flag.String("client-ip-header", "", "trusted reverse-proxy client IP header; leave empty unless the broker is reachable only through that trusted proxy")
	claimAttempts := flag.Int("claim-attempts-per-minute", defaults.ClaimAttemptsPerWindow, "per-client support-code claim attempts per minute; 0 disables")
	globalClaimAttempts := flag.Int("global-claim-attempts-per-minute", defaults.GlobalClaimAttemptsPerWindow, "global support-code claim attempts per minute; 0 disables")
	sessionCreates := flag.Int("session-creates-per-minute", defaults.SessionCreatesPerWindow, "per-client session creates per minute; 0 disables")
	globalSessionCreates := flag.Int("global-session-creates-per-minute", defaults.GlobalSessionCreatesPerWindow, "global session creates per minute; 0 disables")
	maxLiveSessions := flag.Int("max-live-sessions", 10000, "maximum concurrent waiting/approval/active sessions")
	terminalRetention := flag.Duration("terminal-retention", 15*time.Minute, "how long ended/expired sessions and claims remain queryable before pruning")
	flag.Parse()

	if *waitingTTL <= 0 {
		log.Fatal("waiting-ttl must be positive")
	}
	if *claimAttempts < 0 || *globalClaimAttempts < 0 || *sessionCreates < 0 || *globalSessionCreates < 0 {
		log.Fatal("rate limits must be zero or positive")
	}
	if *maxLiveSessions <= 0 {
		log.Fatal("max-live-sessions must be positive")
	}
	if *terminalRetention <= 0 {
		log.Fatal("terminal-retention must be positive")
	}
	if *clientIPHeader != "" && !isLoopbackListen(*listen) {
		log.Fatal("client-ip-header may only be trusted when the broker listen address is loopback-only")
	}

	store := sessionbroker.NewStoreWithOptions(sessionbroker.StoreOptions{
		WaitingTTL:        *waitingTTL,
		MaxLiveSessions:   *maxLiveSessions,
		TerminalRetention: *terminalRetention,
	})
	httpOptions := defaults
	httpOptions.ClientIPHeader = *clientIPHeader
	httpOptions.ClaimAttemptsPerWindow = *claimAttempts
	httpOptions.GlobalClaimAttemptsPerWindow = *globalClaimAttempts
	httpOptions.SessionCreatesPerWindow = *sessionCreates
	httpOptions.GlobalSessionCreatesPerWindow = *globalSessionCreates
	server := &http.Server{
		Addr:              *listen,
		Handler:           sessionbroker.NewHTTPHandlerWithOptions(store, httpOptions),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("Jeris Session Broker listening on %s waiting_ttl=%s claim_limit=%d/min global_claim_limit=%d/min create_limit=%d/min global_create_limit=%d/min max_live_sessions=%d terminal_retention=%s client_ip_header=%q", *listen, waitingTTL.String(), *claimAttempts, *globalClaimAttempts, *sessionCreates, *globalSessionCreates, *maxLiveSessions, terminalRetention.String(), *clientIPHeader)
		errCh <- server.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("broker shutdown: %v", err)
		}
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
