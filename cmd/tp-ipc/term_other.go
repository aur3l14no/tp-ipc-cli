//go:build !darwin && !linux

package main

import "io"

func disableTerminalEcho(_ io.Reader) (restore func(), ok bool) {
	return func() {}, false
}
