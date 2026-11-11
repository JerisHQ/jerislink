package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/JerisHQ/jerislink/support/internal/brokerclient"
	"github.com/JerisHQ/jerislink/support/internal/supportagent"
)

func main() {
	brokerURL := flag.String("broker", "http://127.0.0.1:8781", "Jeris Session Broker base URL")
	transportBinary := flag.String("transport-binary", defaultTransportBinary(), "jeris-support-transport binary")
	pollEvery := flag.Duration("poll-every", time.Second, "broker polling interval")
	startupTimeout := flag.Duration("transport-startup-timeout", 30*time.Second, "Tailcat transport startup timeout")
	singletonAddr := flag.String("singleton-listen", "127.0.0.1:48771", "local single-instance guard listen address; empty disables")
	flag.Parse()

	if *pollEvery <= 0 {
		log.Fatal("poll-every must be positive")
	}

	var singleton net.Listener
	var err error
	if *singletonAddr != "" {
		singleton, err = net.Listen("tcp", *singletonAddr)
		if err != nil {
			log.Fatalf("another JerisLink Support Agent appears to be running (%s unavailable)", *singletonAddr)
		}
		defer singleton.Close()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, err := brokerclient.New(*brokerURL)
	if err != nil {
		log.Fatal(err)
	}
	if err := runAgent(ctx, client, *transportBinary, *startupTimeout, *pollEvery, os.Stdin, os.Stdout); err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func runAgent(ctx context.Context, client *brokerclient.Client, transportBinary string, startupTimeout, pollEvery time.Duration, in io.Reader, out io.Writer) error {
	transport, err := supportagent.StartTransport(ctx, transportBinary, startupTimeout)
	if err != nil {
		return fmt.Errorf("start ephemeral Tailcat identity: %w", err)
	}

	session, err := client.Create(ctx, transport.Address)
	if err != nil {
		_ = transport.Stop()
		return fmt.Errorf("register broker session: %w", err)
	}
	hostToken := session.HostToken
	session.HostToken = ""
	ended := false
	defer func() {
		if !ended {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = client.End(cleanupCtx, session.ID, hostToken)
			cancel()
		}
		_ = transport.Stop()
	}()

	printWaiting(out, session.Code)
	commands := make(chan string, 8)
	go readCommands(in, commands)

	ticker := time.NewTicker(pollEvery)
	defer ticker.Stop()
	lastState := session.State
	lastClaim := session.ClaimID

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-transport.Done():
			return fmt.Errorf("ephemeral Tailcat transport exited: %v", err)
		case line, ok := <-commands:
			if !ok {
				return errors.New("console input closed; ending support session")
			}
			cmd := strings.ToLower(strings.TrimSpace(line))
			switch cmd {
			case "", "status":
				printStatus(out, session)
			case "approve":
				if session.State != "approval_pending" || session.ClaimID == "" {
					fmt.Fprintln(out, "No pending supporter to approve.")
					continue
				}
				updated, err := client.Approve(ctx, session.ID, hostToken, session.ClaimID)
				if err != nil {
					fmt.Fprintf(out, "Approve failed: %v\n", err)
					continue
				}
				session = updated
				fmt.Fprintf(out, "Connected to %s.\n", displaySupporter(session.SupporterName))
				fmt.Fprintln(out, "Command: end")
			case "reject":
				if session.State != "approval_pending" || session.ClaimID == "" {
					fmt.Fprintln(out, "No pending supporter to reject.")
					continue
				}
				updated, err := client.Reject(ctx, session.ID, hostToken, session.ClaimID)
				if err != nil {
					fmt.Fprintf(out, "Reject failed: %v\n", err)
					continue
				}
				session = updated
				fmt.Fprintln(out, "Support request rejected.")
				printWaiting(out, session.Code)
			case "new":
				if session.State == "active" {
					fmt.Fprintln(out, "End the active session before generating a new code.")
					continue
				}
				if err := transport.Stop(); err != nil {
					return fmt.Errorf("stop old Tailcat identity: %w", err)
				}
				fresh, err := supportagent.StartTransport(ctx, transportBinary, startupTimeout)
				if err != nil {
					_, _ = client.End(context.Background(), session.ID, hostToken)
					return fmt.Errorf("start replacement Tailcat identity: %w", err)
				}
				replacement, err := client.Replace(ctx, session.ID, hostToken, fresh.Address)
				if err != nil {
					_ = fresh.Stop()
					_, _ = client.End(context.Background(), session.ID, hostToken)
					return fmt.Errorf("replace broker session: %w", err)
				}
				transport = fresh
				session = replacement
				hostToken = session.HostToken
				session.HostToken = ""
				lastState = session.State
				lastClaim = session.ClaimID
				printWaiting(out, session.Code)
			case "end", "quit", "exit":
				if _, err := client.End(ctx, session.ID, hostToken); err != nil {
					return fmt.Errorf("end broker session: %w", err)
				}
				ended = true
				_ = transport.Stop()
				fmt.Fprintln(out, "Support session ended. Temporary transport credentials destroyed.")
				return nil
			default:
				fmt.Fprintln(out, "Commands: status | approve | reject | new | end")
			}
		case <-ticker.C:
			updated, err := client.Snapshot(ctx, session.ID, hostToken)
			if err != nil {
				fmt.Fprintf(out, "Broker poll failed: %v\n", err)
				continue
			}
			session = updated
			if session.State != lastState || session.ClaimID != lastClaim {
				switch session.State {
				case "approval_pending":
					fmt.Fprintf(out, "Incoming support request from %s. Requested: %s\n", displaySupporter(session.SupporterName), displayCapabilities(session.Capabilities))
					fmt.Fprintln(out, "Type: approve  or  reject")
				case "active":
					fmt.Fprintf(out, "Connected to %s.\n", displaySupporter(session.SupporterName))
				case "expired":
					fmt.Fprintln(out, "Support code expired. Type: new")
				case "waiting":
					printWaiting(out, session.Code)
				case "ended":
					ended = true
					_ = transport.Stop()
					fmt.Fprintln(out, "Support session ended. Temporary transport credentials destroyed.")
					return nil
				}
				lastState = session.State
				lastClaim = session.ClaimID
			}
		}
	}
}

func readCommands(in io.Reader, out chan<- string) {
	defer close(out)
	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		out <- scanner.Text()
	}
}

func printWaiting(out io.Writer, code string) {
	fmt.Fprintln(out, "JerisLink Support")
	fmt.Fprintf(out, "Support Code: %s\n", code)
	fmt.Fprintln(out, "Waiting for supporter...")
	fmt.Fprintln(out, "Commands: new | status | end")
}

func printStatus(out io.Writer, s brokerclient.Session) {
	fmt.Fprintf(out, "State: %s", s.State)
	if s.SupporterName != "" {
		fmt.Fprintf(out, " supporter=%s", displaySupporter(s.SupporterName))
	}
	fmt.Fprintln(out)
}

func displaySupporter(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return "supporter"
	}
	return name
}

func displayCapabilities(caps []string) string {
	if len(caps) == 0 {
		return "none"
	}
	return strings.Join(caps, ", ")
}

func defaultTransportBinary() string {
	exe, err := os.Executable()
	if err != nil {
		return "jeris-support-transport"
	}
	name := "jeris-support-transport-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(filepath.Dir(exe), name)
}
