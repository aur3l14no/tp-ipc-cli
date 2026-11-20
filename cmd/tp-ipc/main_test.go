package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestReadInteractivePasswordNonTTYAndCancel(t *testing.T) {
	in := strings.NewReader("SecretPass!99\r\n")
	var stderr bytes.Buffer
	got, err := readInteractivePassword(context.Background(), in, bufio.NewReader(in), &stderr)
	if err != nil {
		t.Fatalf("readInteractivePassword failed: %v", err)
	}
	if got != "SecretPass!99" {
		t.Fatalf("got %q, want SecretPass!99", got)
	}
	if stderr.Len() != 0 {
		t.Fatalf("expected no extra newline on non-TTY stderr, got %q", stderr.String())
	}

	// Empty password should fail immediately without hitting the network
	emptyIn := strings.NewReader("\n")
	if _, err := readInteractivePassword(context.Background(), emptyIn, bufio.NewReader(emptyIn), &stderr); err == nil {
		t.Fatal("expected error on empty password")
	}

	// Context cancellation while blocked on stdin must return promptly
	pr, pw := io.Pipe()
	defer pw.Close()
	defer pr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = readInteractivePassword(ctx, pr, bufio.NewReader(pr), &stderr)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLiveCommandWebJSONAndShutdown(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("IPC_HOST", "127.0.0.1")
	t.Setenv("IPC_PASSWORD", "testpw")

	ctx, cancel := context.WithCancel(context.Background())
	var stdout, stderr syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"--json", "live", "--no-open"}, strings.NewReader(""), &stdout, &stderr)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(stdout.String(), `"url"`) {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("live command returned error on clean shutdown: %v", err)
	}
	if !strings.Contains(stdout.String(), "?token=") {
		t.Fatalf("expected authenticated live URL in JSON output, got: %s", stdout.String())
	}
}
