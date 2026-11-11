package main

import (
	"bytes"
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
	"syscall"
	"time"
)

const (
	controlToken = "JLS-CONTROL-SMOKE"
	mouseToken   = "JLS-MOUSE-SMOKE"
	videoPrefix  = "JLS-VIDEO-SMOKE"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: qs-tc0-smoke backend|client")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "backend":
		err = runBackend(ctx, os.Args[2:])
	case "client":
		err = runClient(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Fatal(err)
	}
}

func runBackend(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("backend", flag.ContinueOnError)
	control := fs.String("control", "127.0.0.1:48411", "control echo listener")
	mouse := fs.String("mouse", "127.0.0.1:48412", "mouse UDP echo listener")
	video := fs.String("video", "127.0.0.1:48402", "video adapter destination")
	if err := fs.Parse(args); err != nil {
		return err
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	wg.Add(3)
	go func() {
		defer wg.Done()
		errCh <- tcpEcho(ctx, *control)
	}()
	go func() {
		defer wg.Done()
		errCh <- udpEcho(ctx, *mouse)
	}()
	go func() {
		defer wg.Done()
		errCh <- videoSender(ctx, *video)
	}()
	log.Printf("backend ready control=%s mouse=%s video=%s", *control, *mouse, *video)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func tcpEcho(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(c)
	}
}

func udpEcho(ctx context.Context, addr string) error {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", a)
	if err != nil {
		return err
	}
	defer c.Close()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	buf := make([]byte, 1500)
	for {
		n, peer, err := c.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if _, err := c.WriteToUDP(buf[:n], peer); err != nil {
			return err
		}
	}
}

func videoSender(ctx context.Context, addr string) error {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	c, err := net.DialUDP("udp4", nil, a)
	if err != nil {
		return err
	}
	defer c.Close()
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	i := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			i++
			payload := fmt.Sprintf("%s-%04d", videoPrefix, i)
			_, _ = c.Write([]byte(payload))
		}
	}
}

func runClient(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	control := fs.String("control", "127.0.0.1:48400", "adapter control listener")
	mouse := fs.String("mouse", "127.0.0.1:48412", "adapter mouse listener")
	video := fs.String("video", "127.0.0.1:48402", "local video receive address")
	timeout := fs.Duration("timeout", 20*time.Second, "test timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}

	testCtx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	videoResult := make(chan error, 1)
	go func() { videoResult <- waitVideo(testCtx, *video) }()

	if err := retry(testCtx, func() error { return testControl(*control) }); err != nil {
		return fmt.Errorf("CONTROL_FAIL: %w", err)
	}
	fmt.Println("CONTROL_PASS")

	if err := retry(testCtx, func() error { return testMouse(*mouse) }); err != nil {
		return fmt.Errorf("MOUSE_FAIL: %w", err)
	}
	fmt.Println("MOUSE_PASS")

	select {
	case <-testCtx.Done():
		return fmt.Errorf("VIDEO_FAIL: %w", testCtx.Err())
	case err := <-videoResult:
		if err != nil {
			return fmt.Errorf("VIDEO_FAIL: %w", err)
		}
	}
	fmt.Println("VIDEO_PASS")
	fmt.Println("QS_TC0_SMOKE_PASS")
	return nil
}

func testControl(addr string) error {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte(controlToken)
	if _, err := c.Write(payload); err != nil {
		return err
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echo mismatch: %q", got)
	}
	return nil
}

func testMouse(addr string) error {
	target, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte(mouseToken)
	if _, err := c.WriteToUDP(payload, target); err != nil {
		return err
	}
	buf := make([]byte, 256)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(buf[:n], payload) {
		return fmt.Errorf("echo mismatch: %q", buf[:n])
	}
	return nil
}

func waitVideo(ctx context.Context, addr string) error {
	a, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP("udp4", a)
	if err != nil {
		return err
	}
	defer c.Close()
	deadline, ok := ctx.Deadline()
	if ok {
		_ = c.SetReadDeadline(deadline)
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := c.ReadFromUDP(buf)
		if err != nil {
			return err
		}
		if strings.HasPrefix(string(buf[:n]), videoPrefix) {
			return nil
		}
	}
}

func retry(ctx context.Context, fn func() error) error {
	var last error
	for {
		if err := fn(); err == nil {
			return nil
		} else {
			last = err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%v; last error: %w", ctx.Err(), last)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
