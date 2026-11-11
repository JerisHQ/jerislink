package supportcontroller

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

type managedProcess struct {
	cancel   context.CancelFunc
	cmd      *exec.Cmd
	done     chan struct{}
	errMu    sync.Mutex
	exitErr  error
	stopOnce sync.Once
	stopDone chan struct{}
	stopErr  error
}

func newManagedProcess(cancel context.CancelFunc, cmd *exec.Cmd) *managedProcess {
	p := &managedProcess{cancel: cancel, cmd: cmd, done: make(chan struct{}), stopDone: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		p.errMu.Lock()
		p.exitErr = err
		p.errMu.Unlock()
		close(p.done)
	}()
	return p
}

func (p *managedProcess) Done() <-chan struct{} { return p.done }

func (p *managedProcess) Err() error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.exitErr
}

func (p *managedProcess) Stop() error {
	if p == nil {
		return nil
	}
	p.stopOnce.Do(func() {
		defer close(p.stopDone)
		p.cancel()
		select {
		case <-p.done:
			if err := p.Err(); err != nil && !isExpectedStop(err) {
				p.stopErr = err
			}
		case <-time.After(5 * time.Second):
			if p.cmd.Process != nil {
				_ = p.cmd.Process.Kill()
			}
			select {
			case <-p.done:
			case <-time.After(2 * time.Second):
			}
			p.stopErr = errors.New("process did not stop cleanly")
		}
	})
	<-p.stopDone
	return p.stopErr
}

func isExpectedStop(err error) bool {
	if err == nil {
		return true
	}
	text := err.Error()
	return strings.Contains(text, "signal: killed") || strings.Contains(text, "signal: terminated") || strings.Contains(text, "context canceled")
}

type TransportClient struct{ *managedProcess }

type Viewer struct{ *managedProcess }

func StartTransportClient(parent context.Context, binary, descriptor string, startupTimeout time.Duration) (*TransportClient, error) {
	if strings.TrimSpace(binary) == "" {
		return nil, errors.New("transport binary is required")
	}
	if strings.TrimSpace(descriptor) == "" {
		return nil, errors.New("Tailcat descriptor is required")
	}
	if startupTimeout <= 0 {
		startupTimeout = 30 * time.Second
	}

	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, binary,
		"client",
		"--tailcat-stdin",
		"--stats-every", "2s",
		"--health-every", "5s",
		"--health-failures", "2",
		"--restart-backoff", "1s",
		"--restart-backoff-max", "30s",
	)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	proc := newManagedProcess(cancel, cmd)

	if _, err := io.WriteString(stdin, strings.TrimSpace(descriptor)+"\n"); err != nil {
		_ = proc.Stop()
		return nil, fmt.Errorf("write Tailcat descriptor to transport stdin: %w", err)
	}
	_ = stdin.Close()

	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		signaled := false
		for scanner.Scan() {
			line := scanner.Text()
			if !signaled && strings.Contains(line, "tailcat: generation=1 ready") {
				signaled = true
				ready <- nil
			}
		}
		if !signaled {
			if err := scanner.Err(); err != nil {
				ready <- err
			} else {
				ready <- errors.New("transport stderr closed before ready")
			}
		}
	}()

	timer := time.NewTimer(startupTimeout)
	defer timer.Stop()
	select {
	case err := <-ready:
		if err != nil {
			_ = proc.Stop()
			return nil, fmt.Errorf("transport startup: %w", err)
		}
		return &TransportClient{managedProcess: proc}, nil
	case <-proc.Done():
		return nil, fmt.Errorf("transport exited before ready: %v", proc.Err())
	case <-timer.C:
		_ = proc.Stop()
		return nil, errors.New("timed out waiting for Tailcat transport readiness")
	case <-parent.Done():
		_ = proc.Stop()
		return nil, parent.Err()
	}
}

func StartViewer(parent context.Context, binary string) (*Viewer, error) {
	if strings.TrimSpace(binary) == "" {
		return nil, errors.New("Viewer binary is required")
	}
	ctx, cancel := context.WithCancel(parent)
	cmd := exec.CommandContext(ctx, binary,
		"--bind-ip", "127.0.0.1",
		"--source-ip", "127.0.0.1",
		"--port", "48402",
		"--control-port", "48400",
		"--mouse-udp-port", "48412",
		"--mouse-move-transport", "udp",
		"--codec", "hevc",
		"--bitrate-mbps", "20",
		"--startup-timeout-ms", "120000",
		"--idle-timeout-ms", "2147483647",
	)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	return &Viewer{managedProcess: newManagedProcess(cancel, cmd)}, nil
}
