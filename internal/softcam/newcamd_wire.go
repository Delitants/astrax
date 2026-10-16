// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sort"
	"strings"
)

const (
	newcamdMaxWireLength   = 4096 // Excludes the two-byte outer length.
	newcamdMaxFramePayload = 4077 // Ten header bytes, checksum, alignment and IV.
	newcamdCardDataCommand = 0xe4
)

func deriveNewcamdCipher(key [14]byte, mix []byte) (cipher.Block, error) {
	for i, b := range mix {
		key[i%len(key)] ^= b
	}
	block, err := buildCipherFrom14(key[:])
	if err != nil {
		return nil, newcamdError("invalid_configuration", err)
	}
	return block, nil
}

func encodeNewcamdFrame(block cipher.Block, frame newcamdFrame, random io.Reader) ([]byte, error) {
	if len(frame.Payload) < 3 || len(frame.Payload) > newcamdMaxFramePayload {
		return nil, newcamdError("invalid_frame", nil)
	}
	if block == nil || block.BlockSize() != 8 || random == nil {
		return nil, newcamdError("invalid_configuration", nil)
	}
	plainLength := 10 + len(frame.Payload)
	padding := (8 - ((plainLength + 1) % 8)) % 8
	plain := make([]byte, plainLength+padding+1)
	binary.BigEndian.PutUint16(plain[:2], frame.MessageID)
	binary.BigEndian.PutUint16(plain[2:4], frame.ServiceID)
	copy(plain[4:10], frame.Reserved[:])
	copy(plain[10:], frame.Payload)
	declared := len(frame.Payload) - 3
	plain[11] = (frame.Payload[1] & 0xf0) | byte(declared>>8)
	plain[12] = byte(declared)
	if _, err := io.ReadFull(random, plain[plainLength:plainLength+padding]); err != nil {
		return nil, newcamdError("protocol_error", err)
	}
	plain[len(plain)-1] = xorSum(plain[:len(plain)-1])
	var iv [8]byte
	if _, err := io.ReadFull(random, iv[:]); err != nil {
		return nil, newcamdError("protocol_error", err)
	}
	wire := make([]byte, 2+len(plain)+len(iv))
	binary.BigEndian.PutUint16(wire[:2], uint16(len(wire)-2))
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(wire[2:2+len(plain)], plain)
	copy(wire[2+len(plain):], iv[:])
	return wire, nil
}

func decodeNewcamdFrame(block cipher.Block, wire []byte) (newcamdFrame, error) {
	invalid := func() (newcamdFrame, error) { return newcamdFrame{}, newcamdError("invalid_frame", nil) }
	if len(wire) < 18 || len(wire) > 2+newcamdMaxWireLength || block == nil || block.BlockSize() != 8 {
		return invalid()
	}
	outer := int(binary.BigEndian.Uint16(wire[:2]))
	if outer < 16 || outer > newcamdMaxWireLength || outer != len(wire)-2 || (outer-8)%8 != 0 {
		return invalid()
	}
	plain := make([]byte, outer-8)
	cipher.NewCBCDecrypter(block, wire[len(wire)-8:]).CryptBlocks(plain, wire[2:len(wire)-8])
	if len(plain) < 14 || xorSum(plain) != 0 {
		return invalid()
	}
	payloadLength := 3 + (int(plain[11]&0x0f) << 8) + int(plain[12])
	end := 10 + payloadLength
	checksum := len(plain) - 1
	// The checksum is never payload; canonical padding contains at most seven bytes.
	if end > checksum || checksum-end > 7 {
		return invalid()
	}
	frame := newcamdFrame{
		MessageID: binary.BigEndian.Uint16(plain[:2]),
		ServiceID: binary.BigEndian.Uint16(plain[2:4]),
		Payload:   append([]byte(nil), plain[10:end]...),
	}
	copy(frame.Reserved[:], plain[4:10])
	return frame, nil
}

func decodeNewcamdCardData(payload []byte) (newcamdCard, error) {
	if len(payload) < 15 || len(payload) > 2820 || payload[0] != newcamdCardDataCommand {
		return newcamdCard{}, newcamdError("invalid_frame", nil)
	}
	count := int(payload[14])
	declared := int(payload[1]&0x0f)<<8 | int(payload[2])
	if len(payload) != 15+11*count || declared != len(payload)-3 {
		return newcamdCard{}, newcamdError("invalid_frame", nil)
	}
	card := newcamdCard{CAID: binary.BigEndian.Uint16(payload[4:6]), Providers: make([]uint32, 0, count)}
	for i := 0; i < count; i++ {
		p := payload[15+11*i : 18+11*i]
		card.Providers = append(card.Providers, uint32(p[0])<<16|uint32(p[1])<<8|uint32(p[2]))
	}
	sort.Slice(card.Providers, func(i, j int) bool { return card.Providers[i] < card.Providers[j] })
	n := 0
	for _, p := range card.Providers {
		if n == 0 || card.Providers[n-1] != p {
			card.Providers[n] = p
			n++
		}
	}
	card.Providers = card.Providers[:n]
	return card, nil
}

func newcamdLoginPayload(username, cryptPassword string) ([]byte, error) {
	if len(username) == 0 || len(cryptPassword) == 0 || len(username) > newcamdMaxFramePayload-5 ||
		len(cryptPassword) > newcamdMaxFramePayload-5 || len(username)+len(cryptPassword) > newcamdMaxFramePayload-5 ||
		strings.ContainsRune(username, 0) || strings.ContainsRune(cryptPassword, 0) {
		return nil, newcamdError("invalid_configuration", nil)
	}
	payload := make([]byte, 5+len(username)+len(cryptPassword))
	payload[0] = newcamdCmdLogin
	declared := len(payload) - 3
	payload[1], payload[2] = byte(declared>>8), byte(declared)
	copy(payload[3:], username)
	copy(payload[4+len(username):], cryptPassword)
	return payload, nil
}
