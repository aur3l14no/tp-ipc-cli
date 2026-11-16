//go:build darwin || linux

package main

import (
	"io"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

func disableTerminalEcho(r io.Reader) (restore func(), ok bool) {
	f, isFile := r.(*os.File)
	if !isFile {
		return func() {}, false
	}
	fd := f.Fd()
	var orig syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&orig))); errno != 0 {
		return func() {}, false
	}
	noEcho := orig
	noEcho.Lflag &^= syscall.ECHO
	noEcho.Lflag |= syscall.ICANON | syscall.ISIG
	noEcho.Iflag |= syscall.ICRNL
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlWriteTermios, uintptr(unsafe.Pointer(&noEcho))); errno != 0 {
		return func() {}, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, fd, ioctlWriteTermios, uintptr(unsafe.Pointer(&orig)))
		})
	}, true
}
