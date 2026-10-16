// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

// Package cccampeer owns the synthetic recorded acceptance peer for tests only.
package cccampeer

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"astrax/internal/model"
)

// Recording contains byte strings from the immutable independent oracle.
// Callers retain their own provenance checks and public-result assertions.
type Recording struct {
	Username     string
	Password     string
	ExchangesHex []string
}

// Start uses no product codec, injected opener, or deterministic RNG.
// Login proof is byte-exact; random-node-dependent client info/probe are drained
// by fixed lengths. Server transmit state is independent of those client bytes.
func Start(t *testing.T, v Recording, mode string) (model.Softcam, func()) {
	t.Helper()
	steps := make([][]byte, len(v.ExchangesHex))
	for i, x := range v.ExchangesHex {
		b, err := hex.DecodeString(x)
		if err != nil {
			t.Fatal(err)
		}
		steps[i] = b
	}
	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	l.SetDeadline(time.Now().Add(5 * time.Second))
	done, joined := make(chan error, 1), make(chan struct{})
	t.Cleanup(func() { l.Close(); <-joined })
	go func() {
		defer close(joined)
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		err = func() error {
			write := func(b []byte) error { _, err := io.Copy(c, bytes.NewReader(b)); return err }
			read := func(b []byte, exact bool) error {
				got := make([]byte, len(b))
				if _, err := io.ReadFull(c, got); err != nil {
					return err
				}
				if exact && !bytes.Equal(got, b) {
					return fmt.Errorf("independent login proof mismatch")
				}
				return nil
			}
			if err := write(steps[0]); err != nil {
				return err
			}
			for i := 1; i <= 3; i++ {
				if err := read(steps[i], true); err != nil {
					return err
				}
			}
			if mode == "rejected" {
				steps[4][0] ^= 1
			}
			if err := write(steps[4]); err != nil {
				return err
			}
			if mode != "rejected" {
				if err := read(steps[5], false); err != nil {
					return err
				}
				if mode == "malformed" {
					// Recorded empty ack now declares 32769 bytes, before allocation.
					steps[6][2] ^= 0x80
					steps[6][3] ^= 0x81
				}
				if err := write(steps[6]); err != nil {
					return err
				}
				if mode != "malformed" {
					for i := 7; i <= 9; i++ {
						if err := write(steps[i]); err != nil {
							return err
						}
					}
					// Do not send the recorded empty reply until a local probe is observed.
					if err := read(steps[11], false); err != nil {
						return err
					}
					if mode == "unsupported" {
						// 0x06 -> required 0x0b. Compensate plaintext feedback in size bytes.
						for i := 1; i < 4; i++ {
							steps[10][i] ^= 0x0d
						}
					}
					if err := write(steps[10]); err != nil {
						return err
					}
				}
			}
			var extra [1]byte
			if n, err := c.Read(extra[:]); n != 0 || err != io.EOF {
				return fmt.Errorf("client did not close at transcript end: %d %v", n, err)
			}
			return nil
		}()
		done <- err
	}()
	p := model.Softcam{Type: "cccam", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Username: v.Username, Password: v.Password, ConnectTimeoutSec: 1}
	join := func() {
		t.Helper()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(6 * time.Second):
			t.Fatal("recorded peer did not join")
		}
		<-joined
	}
	return p, join
}
