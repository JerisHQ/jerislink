package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/JerisHQ/jerislink/support/internal/brokerclient"
	"github.com/JerisHQ/jerislink/support/internal/supportcontroller"
)

type controllerConfig struct {
	Code             string
	SupporterName    string
	TransportBinary  string
	ViewerBinary     string
	PollEvery        time.Duration
	TransportTimeout time.Duration
}

func main() {
	brokerURL := flag.String("broker", "http://127.0.0.1:8781", "Jeris Session Broker base URL")
	code := flag.String("code", "", "six-digit support code; prompts if omitted")
	supporterName := flag.String("supporter-name", defaultSupporterName(), "supporter identity shown to the supported user")
	transportBinary := flag.String("transport-binary", defaultTransportBinary(), "jeris-support-transport binary")
	viewerBinary := flag.String("viewer-binary", defaultViewerBinary(), "JerisLink Windows Viewer binary")
	pollEvery := flag.Duration("poll-every", 500*time.Millisecond, "broker polling interval")
	transportTimeout := flag.Duration("transport-startup-timeout", 30*time.Second, "Tailcat client startup timeout")
	flag.Parse()

	if *pollEvery <= 0 {
		log.Fatal("poll-every must be positive")
	}
	if *transportTimeout <= 0 {
		log.Fatal("transport-startup-timeout must be positive")
	}

	resolvedCode := strings.TrimSpace(*code)
	if resolvedCode == "" {
		fmt.Print("Support Code: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			log.Fatal(err)
		}
		resolvedCode = strings.TrimSpace(line)
	}
	if resolvedCode == "" {
		log.Fatal("support code is required")
	}

	client, err := brokerclient.New(*brokerURL)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := controllerConfig{
		Code:             resolvedCode,
		SupporterName:    strings.TrimSpace(*supporterName),
		TransportBinary:  *transportBinary,
		ViewerBinary:     *viewerBinary,
		PollEvery:        *pollEvery,
		TransportTimeout: *transportTimeout,
	}
	if cfg.SupporterName == "" {
		cfg.SupporterName = "Supporter"
	}
	if err := runController(ctx, client, cfg, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func runController(ctx context.Context, client *brokerclient.Client, cfg controllerConfig, out io.Writer) error {
	claim, err := client.Claim(ctx, cfg.Code, cfg.SupporterName, []string{"view", "input", "clipboard"})
	if err != nil {
		return fmt.Errorf("claim support code: %w", err)
	}
	claimToken := claim.ClaimToken
	claim.ClaimToken = ""
	left := false
	defer func() {
		if left || claim.ID == "" || claimToken == "" {
			return
		}
		leaveCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _ = client.LeaveClaim(leaveCtx, claim.ID, claimToken)
		cancel()
	}()

	fmt.Fprintf(out, "Support request sent as %s. Waiting for approval...\n", cfg.SupporterName)
	ticker := time.NewTicker(cfg.PollEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current, err := client.ClaimStatus(ctx, claim.ID, claimToken)
			if err != nil {
				return fmt.Errorf("poll support claim: %w", err)
			}
			switch current.State {
			case "pending":
				continue
			case "rejected":
				left = true
				fmt.Fprintln(out, "Support request rejected.")
				return nil
			case "expired":
				left = true
				fmt.Fprintln(out, "Support code expired.")
				return nil
			case "ended":
				left = true
				fmt.Fprintln(out, "Support session ended.")
				return nil
			case "approved":
				if strings.TrimSpace(current.TransportDescriptor) == "" {
					return errors.New("approved claim did not include transport descriptor")
				}
				return runApprovedSession(ctx, client, claim.ID, claimToken, current.TransportDescriptor, cfg, out, &left)
			default:
				return fmt.Errorf("unexpected claim state %q", current.State)
			}
		}
	}
}

func runApprovedSession(ctx context.Context, client *brokerclient.Client, claimID, claimToken, descriptor string, cfg controllerConfig, out io.Writer, left *bool) error {
	fmt.Fprintln(out, "Approved. Establishing secure support transport...")
	transport, err := supportcontroller.StartTransportClient(ctx, cfg.TransportBinary, descriptor, cfg.TransportTimeout)
	descriptor = ""
	if err != nil {
		return fmt.Errorf("start Tailcat client: %w", err)
	}
	defer transport.Stop()

	viewer, err := supportcontroller.StartViewer(ctx, cfg.ViewerBinary)
	if err != nil {
		return fmt.Errorf("start JerisLink Viewer: %w", err)
	}
	defer viewer.Stop()
	fmt.Fprintln(out, "Connected. JerisLink Viewer started.")

	ticker := time.NewTicker(cfg.PollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-transport.Done():
			return fmt.Errorf("support transport stopped unexpectedly: %v", transport.Err())
		case <-viewer.Done():
			return fmt.Errorf("JerisLink Viewer stopped unexpectedly: %v", viewer.Err())
		case <-ticker.C:
			current, err := client.ClaimStatus(ctx, claimID, claimToken)
			if err != nil {
				return fmt.Errorf("poll active support claim: %w", err)
			}
			if current.State == "approved" {
				continue
			}
			if current.State == "ended" || current.State == "expired" || current.State == "rejected" {
				*left = true
				fmt.Fprintln(out, "Support session ended.")
				return nil
			}
			return fmt.Errorf("unexpected active claim state %q", current.State)
		}
	}
}

func defaultSupporterName() string {
	if current, err := user.Current(); err == nil {
		if name := strings.TrimSpace(current.Name); name != "" {
			return name
		}
		if username := strings.TrimSpace(current.Username); username != "" {
			return username
		}
	}
	return "Supporter"
}

func defaultTransportBinary() string {
	return siblingBinary("jeris-support-transport-" + runtime.GOOS + "-" + runtime.GOARCH)
}

func defaultViewerBinary() string {
	if runtime.GOOS == "windows" {
		return siblingBinary("JerislinkSupportViewer")
	}
	return siblingBinary("JerislinkSupportViewer")
}

func siblingBinary(base string) string {
	exe, err := os.Executable()
	if err != nil {
		return base
	}
	name := base
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(exe), name)
}
