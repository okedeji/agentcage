package main

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// AF_VSOCK constants from linux/vm_sockets.h.
const (
	afVsock       = 40
	vsockCIDHost  = 2
	vsockCIDAny   = 0xFFFFFFFF
)

// sockaddrVM mirrors struct sockaddr_vm from linux/vm_sockets.h.
type sockaddrVM struct {
	Family    uint16
	Reserved1 uint16
	Port      uint32
	CID       uint32
	Flags     uint8
	Zero      [3]uint8
}

// vsockListener wraps a raw AF_VSOCK listening socket.
type vsockListener struct {
	fd   int
	port uint32
}

func listenVsock(port uint32) (*vsockListener, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}

	addr := sockaddrVM{
		Family: afVsock,
		Port:   port,
		CID:    vsockCIDAny,
	}

	_, _, errno := syscall.RawSyscall(
		syscall.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("bind(AF_VSOCK, port %d): %w", port, errno)
	}

	if err := syscall.Listen(fd, 8); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("listen(AF_VSOCK, port %d): %w", port, err)
	}

	return &vsockListener{fd: fd, port: port}, nil
}

func (l *vsockListener) Accept() (net.Conn, error) {
	nfd, _, err := syscall.Accept(l.fd)
	if err != nil {
		return nil, fmt.Errorf("accept(AF_VSOCK, port %d): %w", l.port, err)
	}
	f := os.NewFile(uintptr(nfd), fmt.Sprintf("vsock:%d", l.port))
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("FileConn(AF_VSOCK): %w", err)
	}
	return conn, nil
}

func (l *vsockListener) Close() error {
	return syscall.Close(l.fd)
}

func dialVsock(cid, port uint32) (net.Conn, error) {
	fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket(AF_VSOCK): %w", err)
	}

	addr := sockaddrVM{
		Family: afVsock,
		Port:   port,
		CID:    cid,
	}

	// Set a connect timeout by making the socket non-blocking, calling
	// connect, and polling. Simpler: just use a deadline after wrapping.
	_, _, errno := syscall.RawSyscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("connect(AF_VSOCK, cid=%d port=%d): %w", cid, port, errno)
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("vsock:%d:%d", cid, port))
	conn, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		return nil, fmt.Errorf("FileConn(AF_VSOCK): %w", err)
	}

	// FileConn duplicates the fd; the original is closed by f.Close().
	// Set a generous deadline. The hold timeout is enforced host-side.
	_ = conn.SetDeadline(time.Now().Add(25 * time.Hour))

	return conn, nil
}
