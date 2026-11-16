package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

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
