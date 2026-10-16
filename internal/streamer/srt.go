//go:build cgo

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

/*
#cgo pkg-config: srt
#include <srt/srt.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int srt_socket_create() {
    return srt_create_socket();
}

static int srt_socket_configure(int sock) {
    bool no = false;
    struct linger linger_off = {0, 0};
    if (srt_setsockopt(sock, 0, SRTO_SNDSYN, &no, sizeof(no)) < 0) return -1;
    if (srt_setsockopt(sock, 0, SRTO_RCVSYN, &no, sizeof(no)) < 0) return -1;
    return srt_setsockopt(sock, 0, SRTO_LINGER, &linger_off, sizeof(linger_off));
}

static int srt_socket_listen(int sock, const char* host, int port, int backlog) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (host == NULL || strlen(host) == 0) {
        sa.sin_addr.s_addr = INADDR_ANY;
    } else {
        sa.sin_addr.s_addr = inet_addr(host);
    }
    if (srt_bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) return -1;
    return srt_listen(sock, backlog);
}

static int srt_socket_accept(int sock, int* error_code) {
    struct sockaddr_in sa;
    int sa_len = sizeof(sa);
    int client = srt_accept(sock, (struct sockaddr*)&sa, &sa_len);
    *error_code = client < 0 ? srt_getlasterror(NULL) : 0;
    return client;
}

static int srt_socket_send(int sock, const char* data, int len, int* error_code) {
    int result = srt_send(sock, data, len);
    *error_code = result < 0 ? srt_getlasterror(NULL) : 0;
    return result;
}

static int srt_socket_close(int sock) {
    return srt_close(sock);
}

static void srt_init_lib() {
    srt_startup();
}
*/
import "C"
import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"astrax/internal/packetbudget"
)

var srtOnce sync.Once
var errSRTWouldBlock = errors.New("srt operation would block")

// SRTAvailable reports compiled native support, not a successful peer connection.
func SRTAvailable() bool { return true }

func initSRT() {
	srtOnce.Do(func() { C.srt_init_lib() })
}

// Named-field wrapping deliberately does not implement stageCSRTOutput. Native
// Stage C admission stays held until actual native acceptance, not fake-peer QA.
type srtListener struct {
	fanout *srtFanout
}

type nativeSRTAcceptor struct{ socket C.int }
type nativeSRTPeer struct{ socket C.int }

func setupSRTListener(outputURL string, budget *packetbudget.Budget) (*srtListener, error) {
	if budget == nil {
		return nil, ErrStageCSinksUnavailable
	}
	u, err := url.Parse(outputURL)
	if err != nil {
		return nil, fmt.Errorf("parse srt url: %w", err)
	}
	mode := strings.ToLower(u.Query().Get("mode"))
	if mode != "listener" && mode != "" {
		return nil, fmt.Errorf("srt mode %q not supported (only listener)", mode)
	}
	host := u.Hostname()
	if host == "" {
		host = "0.0.0.0"
	}
	portText := u.Port()
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid srt port: %s", portText)
	}
	initSRT()
	socket := C.srt_socket_create()
	if socket < 0 {
		return nil, errors.New("srt_create_socket failed")
	}
	if C.srt_socket_configure(socket) < 0 {
		C.srt_socket_close(socket)
		return nil, errors.New("srt nonblocking configuration failed")
	}
	cHost := C.CString(host)
	defer C.free(unsafe.Pointer(cHost))
	if C.srt_socket_listen(socket, cHost, C.int(port), 5) < 0 {
		C.srt_socket_close(socket)
		return nil, fmt.Errorf("srt listen %s:%d failed", host, port)
	}
	transport := &nativeSRTAcceptor{socket: socket}
	fanout, err := newSRTFanout(transport, budget, time.Now)
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return &srtListener{fanout: fanout}, nil
}

func (a *nativeSRTAcceptor) Accept() (srtPeerTransport, error) {
	var code C.int
	client := C.srt_socket_accept(a.socket, &code)
	if client < 0 {
		if code == C.SRT_EASYNCRCV {
			return nil, errSRTWouldBlock
		}
		return nil, fmt.Errorf("srt accept failed (%d)", int(code))
	}
	if C.srt_socket_configure(client) < 0 {
		C.srt_socket_close(client)
		return nil, errors.New("srt peer nonblocking configuration failed")
	}
	return &nativeSRTPeer{socket: client}, nil
}
func (a *nativeSRTAcceptor) Close() error {
	if C.srt_socket_close(a.socket) < 0 {
		return errors.New("srt listener close failed")
	}
	return nil
}
func (p *nativeSRTPeer) Send(packet []byte, deadline time.Time) (int, error) {
	if len(packet) != 188 {
		return 0, errors.New("srt requires one TS packet")
	}
	for {
		if time.Until(deadline) <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		var code C.int
		// libsrt copies the payload during this nonblocking call. Capture its
		// pthread-local error here, not in a second CGo call on another thread.
		n := C.srt_socket_send(p.socket, (*C.char)(unsafe.Pointer(&packet[0])), C.int(len(packet)), &code)
		runtime.KeepAlive(packet)
		if n >= 0 {
			return int(n), nil
		}
		if code != C.SRT_EASYNCSND {
			return 0, fmt.Errorf("srt send failed (%d)", int(code))
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		// A blocking SNDTIMEO in libsrt 1.4.0 can restart after wakeups. Poll
		// nonblocking sends against Go's monotonic absolute deadline instead.
		timer := time.NewTimer(min(10*time.Millisecond, remaining))
		<-timer.C
	}
}
func (p *nativeSRTPeer) Close() error {
	if C.srt_socket_close(p.socket) < 0 {
		return errors.New("srt peer close failed")
	}
	return nil
}
func (listener *srtListener) Start()                { listener.fanout.Start() }
func (listener *srtListener) Done() <-chan struct{} { return listener.fanout.Done() }
func (listener *srtListener) AcceptLoop()           { listener.Start(); <-listener.Done() }
func (listener *srtListener) Write(packet []byte)   { listener.fanout.Write(packet) }
func (listener *srtListener) Close() error          { return listener.fanout.Close() }
