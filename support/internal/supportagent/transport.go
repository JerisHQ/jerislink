package supportagent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Transport struct {
	Address  string
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	done     chan error
	stopOnce sync.Once
	stopDone chan struct{}
	stopErr  error
}

func StartTransport(parent context.Context, binary string, startupTimeout time.Duration) (*Transport, error) {
	if strings.TrimSpace(binary) == "" {
		return nil, errors.New("transport binary is required")
	}
	if startupTimeout <= 0 {
		startupTimeout = 30 * time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, binary, "server", "--stats-every", "0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	addrCh := make(chan string, 1)
	scanErr := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			if !found && strings.HasPrefix(line, "TAILCAT_ADDR=") {
				found = true
				addrCh <- strings.TrimSpace(strings.TrimPrefix(line, "TAILCAT_ADDR="))
			}
		}
		if err := scanner.Err(); err != nil {
			scanErr <- err
		}
	}()

	timer := time.NewTimer(startupTimeout)
	defer timer.Stop()
	select {
	case addr := <-addrCh:
		if addr == "" {
			cancel()
			return nil, errors.New("transport returned empty Tailcat address")
		}
		return &Transport{Address: addr, cancel: cancel, cmd: cmd, done: done, stopDone: make(chan struct{})}, nil
	case err := <-scanErr:
		cancel()
		return nil, fmt.Errorf("read transport startup: %w", err)
	case err := <-done:
		cancel()
		return nil, fmt.Errorf("transport exited before publishing address: %v", err)
	case <-timer.C:
		cancel()
		return nil, errors.New("timed out waiting for Tailcat address")
	case <-parent.Done():
		cancel()
		return nil, parent.Err()
	}
}

func (t *Transport) Done() <-chan error {
	return t.done
}

func (t *Transport) Stop() error {
	if t == nil {
		return nil
	}
	t.stopOnce.Do(func() {
		defer close(t.stopDone)
		t.cancel()
		select {
		case err := <-t.done:
			if err != nil && !strings.Contains(err.Error(), "signal: killed") {
				t.stopErr = err
			}
		case <-time.After(5 * time.Second):
			if t.cmd.Process != nil {
				_ = t.cmd.Process.Kill()
			}
			select {
			case <-t.done:
			case <-time.After(2 * time.Second):
			}
			t.stopErr = errors.New("transport did not stop cleanly")
		}
	})
	<-t.stopDone
	return t.stopErr
}
