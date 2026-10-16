//go:build linux && cgo && srtqa

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

/*
#cgo pkg-config: srt
#include <srt/srt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

static int qa_srt_option(int sock, SRT_SOCKOPT option, const void* value, int len) {
    return srt_setsockopt(sock, 0, option, value, len);
}
static int qa_srt_configure(int sock, int pressure) {
    bool no = false, yes = true;
    struct linger off = {0, 0};
    if (pressure) {
        SRT_TRANSTYPE type = SRTT_FILE;
        int size = 47104, window = 32;
        if (qa_srt_option(sock, SRTO_TRANSTYPE, &type, sizeof(type)) < 0) return -1;
        if (qa_srt_option(sock, SRTO_MESSAGEAPI, &yes, sizeof(yes)) < 0) return -1;
        if (qa_srt_option(sock, SRTO_TSBPDMODE, &no, sizeof(no)) < 0) return -1;
        if (qa_srt_option(sock, SRTO_TLPKTDROP, &no, sizeof(no)) < 0) return -1;
        if (qa_srt_option(sock, SRTO_FC, &window, sizeof(window)) < 0) return -1;
        if (qa_srt_option(sock, SRTO_SNDBUF, &size, sizeof(size)) < 0) return -1;
        if (qa_srt_option(sock, SRTO_RCVBUF, &size, sizeof(size)) < 0) return -1;
    }
    if (qa_srt_option(sock, SRTO_SNDSYN, &no, sizeof(no)) < 0) return -1;
    if (qa_srt_option(sock, SRTO_RCVSYN, &no, sizeof(no)) < 0) return -1;
    return qa_srt_option(sock, SRTO_LINGER, &off, sizeof(off));
}
static int qa_srt_bind_listener(int sock, int* port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srt_bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) return -1;
    int len = sizeof(sa);
    if (srt_getsockname(sock, (struct sockaddr*)&sa, &len) < 0) return -1;
    *port = ntohs(sa.sin_port);
    return srt_listen(sock, 5);
}
static int qa_srt_connect(int sock, int port, int* error_code) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (srt_bind(sock, (struct sockaddr*)&sa, sizeof(sa)) < 0) { *error_code = srt_getlasterror(NULL); return -1; }
    sa.sin_port = htons(port);
    int result = srt_connect(sock, (struct sockaddr*)&sa, sizeof(sa));
    *error_code = result < 0 ? srt_getlasterror(NULL) : 0;
    return result;
}
static int qa_srt_recv(int sock, char* data, int size, int* error_code) {
    int result = srt_recvmsg(sock, data, size);
    *error_code = result < 0 ? srt_getlasterror(NULL) : 0;
    return result;
}
static int qa_srt_send(int sock, const char* data, int size, int* error_code) {
    int result = srt_send(sock, data, size);
    *error_code = result < 0 ? srt_getlasterror(NULL) : 0;
    return result;
}
static int qa_srt_stats(int sock, long long* drops, int* available) {
    SRT_TRACEBSTATS stats;
    memset(&stats, 0, sizeof(stats));
    if (srt_bstats(sock, &stats, 0) < 0) return -1;
    *drops = (long long)stats.pktSndDropTotal + (long long)stats.pktRcvDropTotal;
    *available = stats.byteAvailRcvBuf;
    return 0;
}
static int qa_srt_sender_queued(int sock) {
    SRT_TRACEBSTATS stats;
    memset(&stats, 0, sizeof(stats));
    return srt_bstats(sock, &stats, 0) < 0 ? -1 : stats.pktSndBuf;
}
static int qa_srt_get_int(int sock, SRT_SOCKOPT option, int* value) {
    int len = sizeof(*value);
    int result = srt_getsockopt(sock, 0, option, value, &len);
    return result < 0 || len != sizeof(*value) ? -1 : 0;
}
static int qa_srt_get_bool(int sock, SRT_SOCKOPT option, int* value) {
    bool flag = false;
    int len = sizeof(flag);
    int result = srt_getsockopt(sock, 0, option, &flag, &len);
    *value = flag;
    return result < 0 || len != sizeof(flag) ? -1 : 0;
}
static int qa_srt_get_congestion(int sock, char* name, int capacity) {
    int len = capacity;
    memset(name, 0, capacity);
    int result = srt_getsockopt(sock, 0, SRTO_CONGESTION, name, &len);
    return result < 0 || len < 1 || len >= capacity ? -1 : 0;
}
static int qa_srt_version(int* version) {
    int sock = srt_create_socket();
    if (sock < 0) return -1;
    int len = sizeof(*version);
    int result = srt_getsockopt(sock, 0, SRTO_VERSION, version, &len);
    int closed = srt_close(sock);
    return result < 0 || closed < 0 ? -1 : 0;
}
static unsigned long long qa_c_heap(int* available) {
#if defined(__GLIBC__) && __GLIBC_PREREQ(2,33)
    struct mallinfo2 info = mallinfo2();
    *available = 1;
    return (unsigned long long)info.uordblks + (unsigned long long)info.hblkhd;
#else
    *available = 0;
    return 0;
#endif
}
*/
import "C"
import (
	"astrax/internal/packetbudget"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"
)

// Opt-in QA only: every address is constructed as loopback in the C helpers.
// No production URL, remote peer, credentials or Stage C capability is exposed.
type qaSRTClient struct {
	socket   C.int
	once     sync.Once
	closeErr error
}

func qaSRTConnect(port int, pressure bool) (*qaSRTClient, error) {
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid QA loopback port")
	}
	sock := C.srt_create_socket()
	if sock < 0 {
		return nil, errors.New("QA create client failed")
	}
	p := C.int(0)
	if pressure {
		p = 1
	}
	if C.qa_srt_configure(sock, p) < 0 {
		C.srt_close(sock)
		return nil, errors.New("QA client options failed")
	}
	var code C.int
	if C.qa_srt_connect(sock, C.int(port), &code) < 0 {
		C.srt_close(sock)
		return nil, fmt.Errorf("QA connect failed (%d)", int(code))
	}
	c := &qaSRTClient{socket: sock}
	until := time.Now().Add(3 * time.Second)
	for C.srt_getsockstate(sock) != C.SRTS_CONNECTED {
		state := C.srt_getsockstate(sock)
		if state == C.SRTS_BROKEN || state == C.SRTS_CLOSED || state == C.SRTS_NONEXIST || time.Now().After(until) {
			_ = c.Close()
			return nil, fmt.Errorf("QA connect did not complete (state %d)", int(state))
		}
		time.Sleep(2 * time.Millisecond)
	}
	return c, nil
}
func (c *qaSRTClient) Receive(deadline time.Time) ([]byte, error) {
	packet := make([]byte, 1500)
	for time.Until(deadline) > 0 {
		var code C.int
		n := C.qa_srt_recv(c.socket, (*C.char)(unsafe.Pointer(&packet[0])), C.int(len(packet)), &code)
		runtime.KeepAlive(packet)
		if n >= 0 {
			return packet[:int(n)], nil
		}
		if code != C.SRT_EASYNCRCV {
			return nil, fmt.Errorf("QA receive failed (%d)", int(code))
		}
		time.Sleep(min(2*time.Millisecond, max(time.Until(deadline), 0)))
	}
	return nil, os.ErrDeadlineExceeded
}
func (c *qaSRTClient) Close() error {
	c.once.Do(func() {
		if C.srt_close(c.socket) < 0 {
			c.closeErr = errors.New("QA client close failed")
		}
	})
	return c.closeErr
}
func qaSRTPressureListener() (*nativeSRTAcceptor, int, error) {
	return qaSRTLoopbackListener(true)
}
func qaSRTLoopbackListener(pressure bool) (*nativeSRTAcceptor, int, error) {
	initSRT()
	sock := C.srt_create_socket()
	if sock < 0 {
		return nil, 0, errors.New("QA create listener failed")
	}
	profile := C.int(0)
	if pressure {
		profile = 1
	}
	if C.qa_srt_configure(sock, profile) < 0 {
		C.srt_close(sock)
		return nil, 0, errors.New("QA pressure listener options failed")
	}
	var port C.int
	if C.qa_srt_bind_listener(sock, &port) < 0 {
		C.srt_close(sock)
		return nil, 0, errors.New("QA listener bind failed")
	}
	return &nativeSRTAcceptor{socket: sock}, int(port), nil
}

func qaSRTOptions(sock C.int) (map[string]any, error) {
	options := make(map[string]any)
	var name [32]C.char
	if C.qa_srt_get_congestion(sock, &name[0], C.int(len(name))) < 0 {
		return nil, errors.New("QA congestion query failed")
	}
	options["congestion"] = C.GoString(&name[0])
	for _, item := range []struct {
		name    string
		option  C.SRT_SOCKOPT
		boolean bool
	}{
		{"message_api", C.SRTO_MESSAGEAPI, true},
		{"send_sync", C.SRTO_SNDSYN, true},
		{"receive_sync", C.SRTO_RCVSYN, true},
		{"tsbpd", C.SRTO_TSBPDMODE, false},
		{"late_drop", C.SRTO_TLPKTDROP, false},
		{"flight_capacity_packets", C.SRTO_FC, false},
		{"send_buffer_api_bytes", C.SRTO_SNDBUF, false},
		{"receive_buffer_api_bytes", C.SRTO_RCVBUF, false},
	} {
		var value C.int
		var result C.int
		if item.boolean {
			result = C.qa_srt_get_bool(sock, item.option, &value)
		} else {
			result = C.qa_srt_get_int(sock, item.option, &value)
		}
		if result < 0 {
			return nil, fmt.Errorf("QA option query failed: %s", item.name)
		}
		if item.boolean || item.name == "tsbpd" || item.name == "late_drop" {
			options[item.name] = value != 0
		} else {
			options[item.name] = int(value)
		}
	}
	return options, nil
}
func qaSRTTrySend(p *nativeSRTPeer, packet []byte) (int, bool, error) {
	if len(packet) != 188 {
		return 0, false, errors.New("invalid QA packet")
	}
	var code C.int
	n := C.qa_srt_send(p.socket, (*C.char)(unsafe.Pointer(&packet[0])), C.int(len(packet)), &code)
	runtime.KeepAlive(packet)
	if n >= 0 {
		return int(n), false, nil
	}
	if code == C.SRT_EASYNCSND {
		return 0, true, nil
	}
	return 0, false, fmt.Errorf("QA send failed (%d)", int(code))
}
func qaSRTVersion() (uint32, error) {
	var version C.int
	if C.qa_srt_version(&version) < 0 {
		return 0, errors.New("QA local SRT version query failed")
	}
	return uint32(version), nil
}
func qaSRTCHeap() (uint64, bool) {
	var available C.int
	n := C.qa_c_heap(&available)
	return uint64(n), available != 0
}
func qaSRTFanout(a *nativeSRTAcceptor) (*srtListener, *packetbudget.Budget, error) {
	b := packetbudget.New(128 << 20)
	h, err := newSRTFanout(a, b, time.Now)
	if err != nil {
		return nil, nil, err
	}
	return &srtListener{fanout: h}, b, nil
}

func qaSRTStats(peer *nativeSRTPeer, c *qaSRTClient) (int64, int, error) {
	var sendDrop, receiveDrop C.longlong
	var unused, available C.int
	if C.srt_getsockstate(peer.socket) != C.SRTS_CONNECTED || C.srt_getsockstate(c.socket) != C.SRTS_CONNECTED {
		return 0, 0, errors.New("QA pair is not connected")
	}
	if C.qa_srt_stats(peer.socket, &sendDrop, &unused) < 0 || C.qa_srt_stats(c.socket, &receiveDrop, &available) < 0 {
		return 0, 0, errors.New("QA socket stats failed")
	}
	return int64(sendDrop + receiveDrop), int(available), nil
}

func qaSRTSenderQueued(peer *nativeSRTPeer) (int, error) {
	n := int(C.qa_srt_sender_queued(peer.socket))
	if n < 0 {
		return 0, errors.New("QA sender occupancy query failed")
	}
	return n, nil
}
