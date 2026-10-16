// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

// Package newcamdpeer is an independent, synthetic, test-only 5.25 peer.
package newcamdpeer

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math/bits"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"astrax/internal/model"
)

type Frame struct {
	ID, SID  uint16
	Reserved [6]byte
	Payload  []byte
}
type Golden struct {
	Key           string
	Frame         Frame
	Wire, Entropy []byte
}
type Exchange struct {
	ID       uint16
	Section  []byte
	SID      uint16
	Response []byte
}
type Recording struct {
	Username, Password, CryptPassword       string
	BaseKey, Challenge                      [14]byte
	LoginAnswer, SessionAnswer, CardPayload []byte
	Golden                                  []Golden
	Exchanges                               []Exchange
}
type Codec struct{ block cipher.Block }

// Expand a bit stream into DES data bits, independently of the product shifts.
func NewCodec(base [14]byte, mix []byte) (*Codec, error) {
	for i, b := range mix {
		base[i%14] ^= b
	}
	var k [24]byte
	for half := 0; half < 2; half++ {
		for octet := 0; octet < 8; octet++ {
			for bit := 0; bit < 7; bit++ {
				src := octet*7 + bit
				k[half*8+octet] |= ((base[half*7+src/8] >> uint(7-src%8)) & 1) << uint(7-bit)
			}
			if bits.OnesCount8(k[half*8+octet])%2 == 0 {
				k[half*8+octet] |= 1
			}
		}
	}
	copy(k[16:], k[:8])
	b, e := des.NewTripleDESCipher(k[:])
	return &Codec{block: b}, e
}
func (c *Codec) encode(f Frame, entropy io.Reader) ([]byte, error) {
	if len(f.Payload) < 3 || len(f.Payload) > 4077 {
		return nil, errors.New("peer payload bound")
	}
	n := 10 + len(f.Payload)
	padded := ((n + 1 + 7) / 8) * 8
	p := make([]byte, padded)
	binary.BigEndian.PutUint16(p, f.ID)
	binary.BigEndian.PutUint16(p[2:], f.SID)
	copy(p[4:10], f.Reserved[:])
	copy(p[10:], f.Payload)
	body := len(f.Payload) - 3
	p[11] = f.Payload[1]&0xf0 | byte(body>>8)
	p[12] = byte(body)
	if _, e := io.ReadFull(entropy, p[n:len(p)-1]); e != nil {
		return nil, e
	}
	for _, b := range p[:len(p)-1] {
		p[len(p)-1] ^= b
	}
	iv := make([]byte, 8)
	if _, e := io.ReadFull(entropy, iv); e != nil {
		return nil, e
	}
	wire := make([]byte, 2+len(p)+8)
	binary.BigEndian.PutUint16(wire, uint16(len(wire)-2))
	cipher.NewCBCEncrypter(c.block, iv).CryptBlocks(wire[2:2+len(p)], p)
	copy(wire[2+len(p):], iv)
	return wire, nil
}
func (c *Codec) decode(w []byte) (Frame, error) {
	bad := func() (Frame, error) { return Frame{}, errors.New("peer invalid frame") }
	if len(w) < 18 || len(w) > 4098 {
		return bad()
	}
	n := int(binary.BigEndian.Uint16(w))
	if n != len(w)-2 || (n-8)%8 != 0 {
		return bad()
	}
	p := make([]byte, n-8)
	cipher.NewCBCDecrypter(c.block, w[len(w)-8:]).CryptBlocks(p, w[2:len(w)-8])
	if len(p) < 14 {
		return bad()
	}
	var x byte
	for _, b := range p {
		x ^= b
	}
	if x != 0 {
		return bad()
	}
	end := 13 + int(p[11]&15)*256 + int(p[12])
	if end > len(p)-1 || len(p)-1-end > 7 {
		return bad()
	}
	f := Frame{ID: binary.BigEndian.Uint16(p), SID: binary.BigEndian.Uint16(p[2:]), Payload: append([]byte(nil), p[10:end]...)}
	copy(f.Reserved[:], p[4:10])
	return f, nil
}
func (c *Codec) ReadFrame(r io.Reader) (Frame, error) {
	var h [2]byte
	if _, e := io.ReadFull(r, h[:]); e != nil {
		return Frame{}, e
	}
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 16 || n > 4096 {
		return Frame{}, errors.New("peer outer bound")
	}
	w := make([]byte, n+2)
	copy(w, h[:])
	if _, e := io.ReadFull(r, w[2:]); e != nil {
		return Frame{}, e
	}
	return c.decode(w)
}
func (c *Codec) WriteFrame(w io.Writer, f Frame) error {
	b, e := c.encode(f, rand.Reader)
	if e != nil {
		return e
	}
	n, e := w.Write(b)
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}
func Replay(r Recording) error {
	login, e := NewCodec(r.BaseKey, r.Challenge[:])
	if e != nil {
		return e
	}
	session, e := NewCodec(r.BaseKey, []byte(r.CryptPassword))
	if e != nil {
		return e
	}
	for _, v := range []struct {
		c      *Codec
		answer []byte
	}{{login, r.LoginAnswer}, {session, r.SessionAnswer}} {
		var out [8]byte
		v.c.block.Encrypt(out[:], []byte{0, 1, 2, 3, 4, 5, 6, 7})
		if !bytes.Equal(out[:], v.answer) {
			return errors.New("peer C block answer mismatch")
		}
	}
	if len(r.Golden) < 4 {
		return errors.New("peer golden recording missing")
	}
	for _, g := range r.Golden {
		c := session
		if g.Key == "login" {
			c = login
		}
		b, e := c.encode(g.Frame, bytes.NewReader(g.Entropy))
		if e != nil || !bytes.Equal(b, g.Wire) {
			return errors.New("peer C wire answer mismatch")
		}
		f, e := c.decode(g.Wire)
		if e != nil || !reflect.DeepEqual(f, g.Frame) {
			return errors.New("peer C decoded answer mismatch")
		}
	}
	return nil
}
func Handshake(c net.Conn, r Recording, mode string) (*Codec, error) {
	if e := Replay(r); e != nil {
		return nil, e
	}
	login, e := NewCodec(r.BaseKey, r.Challenge[:])
	if e != nil {
		return nil, e
	}
	if _, e = c.Write(r.Challenge[:]); e != nil {
		return nil, e
	}
	f, e := login.ReadFrame(c)
	if e != nil {
		return nil, e
	}
	var expected []byte
	expected = append(expected, 0xe0, 0, 0)
	expected = append(expected, []byte(r.Username)...)
	expected = append(expected, 0)
	expected = append(expected, []byte(r.CryptPassword)...)
	expected = append(expected, 0)
	body := len(expected) - 3
	expected[1] = byte(body >> 8)
	expected[2] = byte(body)
	if f.ID != 0 || f.SID != 0x8888 || f.Reserved != ([6]byte{}) || !bytes.Equal(f.Payload, expected) {
		return nil, errors.New("peer login contract mismatch")
	}
	ack := Frame{Payload: []byte{0xe1, 0, 0}}
	switch mode {
	case "nak":
		ack.Payload[0] = 0xe2
	case "ack-id":
		ack.ID = 9
	case "ack-command":
		ack.Payload[0] = 0xfd
	}
	if e = login.WriteFrame(c, ack); e != nil {
		return nil, e
	}
	session, e := NewCodec(r.BaseKey, []byte(r.CryptPassword))
	if e != nil {
		return nil, e
	}
	if mode == "nak" || mode == "ack-id" || mode == "ack-command" {
		return session, nil
	}
	f, e = session.ReadFrame(c)
	if e != nil {
		return nil, e
	}
	if f.ID != 1 || f.SID != 0 || f.Reserved != ([6]byte{}) || !bytes.Equal(f.Payload, []byte{0xe3, 0, 0}) {
		return nil, errors.New("peer card request contract mismatch")
	}
	if mode == "discovery-timeout" || mode == "hold-discovery" {
		return session, nil
	}
	card := Frame{ID: 1, Payload: append([]byte(nil), r.CardPayload...)}
	switch mode {
	case "card-id":
		card.ID++
	case "card-command":
		card.Payload = []byte{0xfd, 0, 0}
	case "card-malformed":
		card.Payload = card.Payload[:len(card.Payload)-1]
	}
	if e = session.WriteFrame(c, card); e != nil {
		return nil, e
	}
	return session, nil
}
func Start(t *testing.T, r Recording, mode string) (model.Softcam, func()) {
	t.Helper()
	if e := Replay(r); e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var mu sync.Mutex
	var conn net.Conn
	var stopped bool
	var err error
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := l.Accept()
		if e != nil {
			mu.Lock()
			if !stopped {
				err = e
			}
			mu.Unlock()
			return
		}
		mu.Lock()
		conn = c
		stop := stopped
		mu.Unlock()
		defer c.Close()
		if stop {
			return
		}
		c.SetDeadline(time.Now().Add(15 * time.Second))
		codec, e := Handshake(c, r, mode)
		next := 0
		if e == nil {
			for {
				f, re := codec.ReadFrame(c)
				if re == io.EOF {
					if next != len(r.Exchanges) {
						e = errors.New("peer missing scripted ECM")
					}
					break
				}
				if re != nil {
					e = re
					break
				}
				if mode == "normal" && (f.Payload[0] == 0x80 || f.Payload[0] == 0x81) {
					if next >= len(r.Exchanges) {
						e = errors.New("peer unexpected ECM")
						break
					}
					x := r.Exchanges[next]
					next++
					if f.ID != x.ID || f.SID != x.SID || f.Reserved != ([6]byte{}) || !bytes.Equal(f.Payload, x.Section) {
						e = errors.New("peer ECM contract mismatch")
						break
					}
					if e = codec.WriteFrame(c, Frame{ID: f.ID, Payload: x.Response}); e != nil {
						break
					}
					continue
				}
				if mode != "normal" || f.Payload[0] != 0xfd || len(f.Payload) != 3 {
					e = errors.New("peer unexpected extra request")
					break
				}
				if e = codec.WriteFrame(c, f); e != nil {
					break
				}
			}
		}
		mu.Lock()
		if e != nil && (!stopped || !errors.Is(e, net.ErrClosed)) {
			err = e
		}
		mu.Unlock()
	}()
	var once sync.Once
	join := func() {
		once.Do(func() {
			mu.Lock()
			stopped = true
			c := conn
			mu.Unlock()
			l.Close()
			if c != nil {
				c.Close()
			}
			<-done
			mu.Lock()
			e := err
			mu.Unlock()
			if e != nil {
				t.Error(e)
			}
		})
	}
	t.Cleanup(join)
	p := model.Softcam{Type: "newcamd", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, Username: r.Username, Password: r.Password, DESKey: hex.EncodeToString(r.BaseKey[:]), ConnectTimeoutSec: 2, Enabled: true}
	return p, join
}
