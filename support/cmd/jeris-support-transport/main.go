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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tailscale/tailcat"
)

const (
	tailcatControlPort uint16 = 38400
	tailcatVideoPort   uint16 = 38402
	tailcatMousePort   uint16 = 38412
	videoBootstrap            = "JLS1-VIDEO"
)

type counters struct {
	videoPackets   atomic.Uint64
	videoBytes     atomic.Uint64
	mouseUp        atomic.Uint64
	mouseDown      atomic.Uint64
	controlConn    atomic.Uint64
	generation     atomic.Uint64
	healthOK       atomic.Uint64
	healthFail     atomic.Uint64
	clientRebuilds atomic.Uint64
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(ctx, os.Args[2:])
	case "client":
		err = runClient(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `JerisLink Support Tailcat transport PoC

Usage:
  jeris-support-transport server [flags]
  jeris-support-transport client --tailcat <tc-address> [flags]

Server defaults (macOS QS-TC0):
  control target 127.0.0.1:48411
  mouse target   127.0.0.1:48412
  video listen   127.0.0.1:48402

Client defaults (Windows QS-TC0):
  control listen 127.0.0.1:48400
  mouse listen   127.0.0.1:48412
  video target   127.0.0.1:48402
`)
}

func runServer(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	controlTarget := fs.String("control-target", "127.0.0.1:48411", "local JerisLink control TCP target")
	mouseTarget := fs.String("mouse-target", "127.0.0.1:48412", "local JerisLink mouse UDP target")
	videoListen := fs.String("video-listen", "127.0.0.1:48402", "local UDP socket receiving JerisLink video packets")
	udpIdle := fs.Duration("udp-idle", 10*time.Minute, "Tailcat server-side UDP flow idle timeout")
	statsEvery := fs.Duration("stats-every", 5*time.Second, "statistics log interval; 0 disables")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var c counters
	videoHub, err := newVideoHub(ctx, *videoListen, &c)
	if err != nil {
		return err
	}
	defer videoHub.Close()

	s := &tailcat.Server{UDPIdleTimeout: *udpIdle}
	s.OnTCP = func(port uint16) func(net.Conn) {
		if port != tailcatControlPort {
			return nil
		}
		return func(remote net.Conn) {
			c.controlConn.Add(1)
			defer remote.Close()
			local, err := net.Dial("tcp", *controlTarget)
			if err != nil {
				log.Printf("control: local dial %s failed: %v", *controlTarget, err)
				return
			}
			defer local.Close()
			log.Printf("control: connected Tailcat peer -> %s", *controlTarget)
			proxyStream(remote, local)
		}
	}
	s.OnUDP = func(port uint16) func(tailcat.ConnPacketConn) {
		switch port {
		case tailcatVideoPort:
			return func(remote tailcat.ConnPacketConn) {
				if err := videoHub.Attach(ctx, remote); err != nil && !isClosed(err) {
					log.Printf("video: flow ended: %v", err)
				}
			}
		case tailcatMousePort:
			return func(remote tailcat.ConnPacketConn) {
				if err := serveMouseFlow(ctx, remote, *mouseTarget, &c); err != nil && !isClosed(err) {
					log.Printf("mouse: flow ended: %v", err)
				}
			}
		default:
			return nil
		}
	}

	if err := s.Start(); err != nil {
		return fmt.Errorf("tailcat server start: %w", err)
	}
	defer s.Close()

	fmt.Printf("TAILCAT_ADDR=%s\n", s.TailcatAddr())
	log.Printf("server: control=%s mouse=%s video=%s udpIdle=%s", *controlTarget, *mouseTarget, *videoListen, *udpIdle)
	startStats(ctx, *statsEvery, "server", &c)
	<-ctx.Done()
	return ctx.Err()
}

type videoHub struct {
	mu      sync.Mutex
	local   *net.UDPConn
	remote  tailcat.ConnPacketConn
	counter *counters
}

func newVideoHub(ctx context.Context, listen string, c *counters) (*videoHub, error) {
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return nil, err
	}
	local, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("video listen %s: %w", listen, err)
	}
	h := &videoHub{local: local, counter: c}
	log.Printf("video: persistent local listener %s", listen)
	go h.forwardLocalVideo(ctx)
	return h, nil
}

func (h *videoHub) Close() {
	h.mu.Lock()
	remote := h.remote
	h.remote = nil
	h.mu.Unlock()
	if remote != nil {
		_ = remote.Close()
	}
	_ = h.local.Close()
}

func (h *videoHub) Attach(ctx context.Context, remote tailcat.ConnPacketConn) error {
	defer remote.Close()
	if err := remote.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}
	buf := make([]byte, tailcat.MaxUDPPayload)
	n, err := remote.Read(buf)
	if err != nil {
		return fmt.Errorf("bootstrap read: %w", err)
	}
	if string(buf[:n]) != videoBootstrap {
		return fmt.Errorf("invalid bootstrap datagram")
	}
	_ = remote.SetReadDeadline(time.Time{})

	h.mu.Lock()
	old := h.remote
	h.remote = remote
	h.mu.Unlock()
	if old != nil && old != remote {
		_ = old.Close()
	}
	log.Printf("video: active Tailcat flow attached")

	// Keep the flow alive and notice peer disconnects. Client-to-server video
	// packets are control/keepalive only; screen data travels in the opposite
	// direction via forwardLocalVideo.
	for {
		select {
		case <-ctx.Done():
			h.detach(remote)
			return ctx.Err()
		default:
		}
		if _, err := remote.Read(buf); err != nil {
			h.detach(remote)
			return err
		}
	}
}

func (h *videoHub) detach(remote tailcat.ConnPacketConn) {
	h.mu.Lock()
	if h.remote == remote {
		h.remote = nil
	}
	h.mu.Unlock()
}

func (h *videoHub) forwardLocalVideo(ctx context.Context) {
	buf := make([]byte, tailcat.MaxUDPPayload)
	for {
		n, _, err := h.local.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() == nil && !isClosed(err) {
				log.Printf("video: local listener ended: %v", err)
			}
			return
		}
		h.mu.Lock()
		remote := h.remote
		h.mu.Unlock()
		if remote == nil {
			continue
		}
		if _, err := remote.Write(buf[:n]); err != nil {
			log.Printf("video: Tailcat delivery dropped: %v", err)
			h.detach(remote)
			_ = remote.Close()
			continue
		}
		h.counter.videoPackets.Add(1)
		h.counter.videoBytes.Add(uint64(n))
	}
}

func serveMouseFlow(ctx context.Context, remote tailcat.ConnPacketConn, target string, c *counters) error {
	defer remote.Close()
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return err
	}
	local, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	defer local.Close()
	log.Printf("mouse: Tailcat flow <-> %s", target)

	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, tailcat.MaxUDPPayload)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := local.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
			c.mouseUp.Add(1)
		}
	}()
	go func() {
		buf := make([]byte, tailcat.MaxUDPPayload)
		for {
			n, err := local.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			if _, err := remote.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
			c.mouseDown.Add(1)
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func runClient(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	addr := fs.String("tailcat", "", "Tailcat server address")
	addrFile := fs.String("tailcat-file", "", "read Tailcat server address from a file")
	addrStdin := fs.Bool("tailcat-stdin", false, "read Tailcat server address from stdin")
	controlListen := fs.String("control-listen", "127.0.0.1:48400", "local TCP listener for JerisLink Viewer control")
	mouseListen := fs.String("mouse-listen", "127.0.0.1:48412", "local UDP listener for JerisLink Viewer mouse/cursor channel")
	videoTarget := fs.String("video-target", "127.0.0.1:48402", "local JerisLink Viewer UDP video target")
	statsEvery := fs.Duration("stats-every", 5*time.Second, "statistics log interval; 0 disables")
	healthEvery := fs.Duration("health-every", 15*time.Second, "Tailcat session health probe interval; 0 disables")
	healthFailures := fs.Int("health-failures", 2, "consecutive Tailcat health probe failures before rebuilding the client")
	restartBackoff := fs.Duration("restart-backoff", time.Second, "base delay before rebuilding a failed Tailcat client generation")
	restartBackoffMax := fs.Duration("restart-backoff-max", 30*time.Second, "maximum exponential delay after consecutive Tailcat startup failures")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *healthFailures < 1 {
		return errors.New("--health-failures must be at least 1")
	}
	if *restartBackoff <= 0 {
		return errors.New("--restart-backoff must be greater than 0")
	}
	if *restartBackoffMax < *restartBackoff {
		return errors.New("--restart-backoff-max must be greater than or equal to --restart-backoff")
	}
	resolvedAddr, err := resolveTailcatAddress(*addr, *addrFile, *addrStdin, os.Stdin)
	if err != nil {
		return err
	}
	*addr = resolvedAddr

	var c counters

	startStats(ctx, *statsEvery, "client", &c)
	log.Printf(
		"client: control=%s mouse=%s video=%s healthEvery=%s healthFailures=%d",
		*controlListen, *mouseListen, *videoTarget, *healthEvery, *healthFailures,
	)

	startupFailureStreak := 0
	for generation := uint64(1); ; generation++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.generation.Store(generation)
		ready, err := runClientGeneration(
			ctx,
			tailcat.Addr(*addr),
			*controlListen,
			*mouseListen,
			*videoTarget,
			*healthEvery,
			*healthFailures,
			&c,
			generation,
		)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		c.clientRebuilds.Add(1)
		rebuildDelay, nextFailureStreak := nextRestartDelay(
			ready, startupFailureStreak, *restartBackoff, *restartBackoffMax,
		)
		startupFailureStreak = nextFailureStreak
		log.Printf(
			"tailcat: generation=%d ended: %v; rebuilding in %s startup_failure_streak=%d",
			generation, err, rebuildDelay, startupFailureStreak,
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(rebuildDelay):
		}
	}
}

func resolveTailcatAddress(addr, addrFile string, addrStdin bool, stdin io.Reader) (string, error) {
	sources := 0
	if strings.TrimSpace(addr) != "" {
		sources++
	}
	if strings.TrimSpace(addrFile) != "" {
		sources++
	}
	if addrStdin {
		sources++
	}
	if sources == 0 {
		return "", errors.New("one of --tailcat, --tailcat-file, or --tailcat-stdin is required")
	}
	if sources > 1 {
		return "", errors.New("use only one of --tailcat, --tailcat-file, or --tailcat-stdin")
	}

	if strings.TrimSpace(addr) != "" {
		return strings.TrimSpace(addr), nil
	}
	if strings.TrimSpace(addrFile) != "" {
		b, err := os.ReadFile(addrFile)
		if err != nil {
			return "", fmt.Errorf("read --tailcat-file: %w", err)
		}
		resolved := strings.TrimSpace(string(b))
		if resolved == "" {
			return "", errors.New("Tailcat address is empty")
		}
		return resolved, nil
	}

	reader := bufio.NewReader(io.LimitReader(stdin, 64<<10))
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read --tailcat-stdin: %w", err)
	}
	resolved := strings.TrimSpace(line)
	if resolved == "" {
		return "", errors.New("Tailcat address from stdin is empty")
	}
	return resolved, nil
}

func runClientGeneration(
	ctx context.Context,
	addr tailcat.Addr,
	controlListen string,
	mouseListen string,
	videoTarget string,
	healthEvery time.Duration,
	healthFailures int,
	c *counters,
	generation uint64,
) (bool, error) {
	cl := tailcat.NewClient(addr)
	closed := false
	closeClient := func() {
		if closed {
			return
		}
		closed = true
		_ = cl.Close()
	}
	defer closeClient()

	ready, err := cl.Ping(ctx)
	if err != nil {
		return false, fmt.Errorf("initial Tailcat ping: %w", err)
	}
	log.Printf("tailcat: generation=%d ready derp_rtt=%s", generation, ready.Latency)

	genCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	startChannel := func(name string, run func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			superviseChannel(genCtx, name, run)
		}()
	}
	startChannel("control", func() error {
		return clientControl(genCtx, cl, controlListen, c)
	})
	startChannel("mouse", func() error {
		return clientMouse(genCtx, cl, mouseListen, c)
	})
	startChannel("video", func() error {
		return clientVideo(genCtx, cl, videoTarget, c)
	})

	healthErr := monitorTailcat(
		genCtx,
		healthEvery,
		healthFailures,
		func(probeCtx context.Context) error {
			// After a Client's first successful Ping, Tailcat's meowWait
			// channel stays closed, so later Ping calls are useful as a
			// best-effort re-registration nudge but not as health evidence.
			// The DiscoPing round trip below is the actual health verdict.
			_, _ = cl.Ping(probeCtx)
			select {
			case <-probeCtx.Done():
				return probeCtx.Err()
			case <-time.After(200 * time.Millisecond):
			}
			discoCtx, discoCancel := context.WithTimeout(probeCtx, 5*time.Second)
			defer discoCancel()
			if _, err := cl.DiscoPing(discoCtx); err != nil {
				return fmt.Errorf("data-path ping: %w", err)
			}
			return nil
		},
		c,
		generation,
	)

	cancel()
	closeClient()
	wg.Wait()
	if ctx.Err() != nil {
		return true, ctx.Err()
	}
	return true, healthErr
}

func nextRestartDelay(ready bool, failureStreak int, base, maximum time.Duration) (time.Duration, int) {
	if ready {
		return base, 0
	}
	failureStreak++
	return exponentialBackoff(base, maximum, failureStreak), failureStreak
}

func exponentialBackoff(base, maximum time.Duration, failureStreak int) time.Duration {
	if failureStreak <= 1 {
		return base
	}
	delay := base
	for i := 1; i < failureStreak; i++ {
		if delay >= maximum || delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func monitorTailcat(
	ctx context.Context,
	every time.Duration,
	failureLimit int,
	probe func(context.Context) error,
	c *counters,
	generation uint64,
) error {
	if every <= 0 {
		<-ctx.Done()
		return ctx.Err()
	}

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			err := probe(ctx)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if err != nil {
				consecutiveFailures++
				c.healthFail.Add(1)
				log.Printf(
					"tailcat: generation=%d health failure=%d/%d: %v",
					generation, consecutiveFailures, failureLimit, err,
				)
				if consecutiveFailures >= failureLimit {
					return fmt.Errorf(
						"Tailcat session unhealthy after %d consecutive probes: %w",
						consecutiveFailures, err,
					)
				}
				continue
			}

			c.healthOK.Add(1)
			if consecutiveFailures > 0 {
				log.Printf(
					"tailcat: generation=%d health recovered after %d failure(s)",
					generation, consecutiveFailures,
				)
			}
			consecutiveFailures = 0
		}
	}
}

func superviseChannel(ctx context.Context, name string, run func() error) {
	for {
		err := run()
		if ctx.Err() != nil {
			return
		}
		log.Printf("%s: channel ended: %v; retrying in 1s", name, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

func clientControl(ctx context.Context, cl *tailcat.Client, listen string, c *counters) error {
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return fmt.Errorf("control listen %s: %w", listen, err)
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	log.Printf("control: local listener %s", listen)
	for {
		local, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func(local net.Conn) {
			defer local.Close()
			remote, err := cl.DialTCPPort(ctx, tailcatControlPort)
			if err != nil {
				log.Printf("control: Tailcat dial failed: %v", err)
				return
			}
			defer remote.Close()
			c.controlConn.Add(1)
			log.Printf("control: viewer connected -> Tailcat")
			proxyStream(local, remote)
		}(local)
	}
}

func clientMouse(ctx context.Context, cl *tailcat.Client, listen string, c *counters) error {
	addr, err := net.ResolveUDPAddr("udp4", listen)
	if err != nil {
		return err
	}
	local, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("mouse listen %s: %w", listen, err)
	}
	defer local.Close()
	remote, err := cl.DialUDPPort(ctx, tailcatMousePort)
	if err != nil {
		return fmt.Errorf("mouse Tailcat dial: %w", err)
	}
	defer remote.Close()
	log.Printf("mouse: local listener %s", listen)

	var peerMu sync.RWMutex
	var peer *net.UDPAddr
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, tailcat.MaxUDPPayload)
		for {
			n, p, err := local.ReadFromUDP(buf)
			if err != nil {
				errCh <- err
				return
			}
			peerMu.Lock()
			peer = p
			peerMu.Unlock()
			if _, err := remote.Write(buf[:n]); err != nil {
				errCh <- err
				return
			}
			c.mouseUp.Add(1)
		}
	}()
	go func() {
		buf := make([]byte, tailcat.MaxUDPPayload)
		for {
			n, err := remote.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			peerMu.RLock()
			p := peer
			peerMu.RUnlock()
			if p == nil {
				continue
			}
			if _, err := local.WriteToUDP(buf[:n], p); err != nil {
				errCh <- err
				return
			}
			c.mouseDown.Add(1)
		}
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func clientVideo(ctx context.Context, cl *tailcat.Client, target string, c *counters) error {
	remote, err := cl.DialUDPPort(ctx, tailcatVideoPort)
	if err != nil {
		return fmt.Errorf("video Tailcat dial: %w", err)
	}
	defer remote.Close()
	if _, err := remote.Write([]byte(videoBootstrap)); err != nil {
		return fmt.Errorf("video bootstrap: %w", err)
	}
	addr, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		return err
	}
	local, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return fmt.Errorf("video local dial %s: %w", target, err)
	}
	defer local.Close()
	log.Printf("video: Tailcat -> %s", target)

	buf := make([]byte, tailcat.MaxUDPPayload)
	for {
		n, err := remote.Read(buf)
		if err != nil {
			return err
		}
		if _, err := local.Write(buf[:n]); err != nil {
			// The local Viewer may not have bound its UDP socket yet. Video is
			// disposable, so a local ICMP/connection-refused race must not tear
			// down the Tailcat session; later packets can succeed once the Viewer
			// starts listening.
			log.Printf("video: local delivery dropped: %v", err)
			continue
		}
		c.videoPackets.Add(1)
		c.videoBytes.Add(uint64(n))
	}
}

func proxyStream(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

func startStats(ctx context.Context, every time.Duration, role string, c *counters) {
	if every <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("stats role=%s video_packets=%d video_bytes=%d mouse_up=%d mouse_down=%d control_conn=%d generation=%d health_ok=%d health_fail=%d client_rebuilds=%d",
					role,
					c.videoPackets.Load(),
					c.videoBytes.Load(),
					c.mouseUp.Load(),
					c.mouseDown.Load(),
					c.controlConn.Load(),
					c.generation.Load(),
					c.healthOK.Load(),
					c.healthFail.Load(),
					c.clientRebuilds.Load(),
				)
			}
		}
	}()
}

func isClosed(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}
