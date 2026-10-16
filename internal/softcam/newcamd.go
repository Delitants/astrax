// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/bits"
	"strings"
)

const (
	newcamdHandshakeLen = 14
	newcamdHeaderLen    = 8
	newcamdFirstCmd     = 0xe0
	newcamdCmdLogin     = newcamdFirstCmd
	newcamdCmdLoginAck  = newcamdFirstCmd + 1
	newcamdCmdLoginNak  = newcamdFirstCmd + 2
	newcamdCmdKeepAlive = newcamdFirstCmd + 0x1d
	newcamdCmdGetCAID   = newcamdFirstCmd + 3
	newcamdCmdCAIDAck   = newcamdFirstCmd + 4
)

func parseDESKey(raw string) ([]byte, error) {
	clean := strings.TrimSpace(raw)
	clean = strings.NewReplacer(" ", "", ":", "", "-", "").Replace(clean)
	if len(clean) != 28 {
		return nil, fmt.Errorf("des_key must be 14-byte hex (28 chars)")
	}
	decoded, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("invalid des_key hex")
	}
	if len(decoded) != 14 {
		return nil, fmt.Errorf("des_key must decode to 14 bytes")
	}
	return decoded, nil
}

func buildCipherFrom14(key14 []byte) (cipher.Block, error) {
	if len(key14) != 14 {
		return nil, fmt.Errorf("invalid 14-byte key length")
	}
	spread := spread14To16(key14)
	for i := range spread {
		spread[i] = ensureOddParity(spread[i])
	}
	key24 := make([]byte, 24)
	copy(key24[:16], spread)
	copy(key24[16:], spread[:8])
	block, err := des.NewTripleDESCipher(key24)
	if err != nil {
		return nil, fmt.Errorf("newcamd cipher init failed: %w", err)
	}
	return block, nil
}

func spread14To16(in []byte) []byte {
	out := make([]byte, 16)
	out[0] = in[0] & 0xfe
	out[1] = ((in[0] << 7) | (in[1] >> 1)) & 0xfe
	out[2] = ((in[1] << 6) | (in[2] >> 2)) & 0xfe
	out[3] = ((in[2] << 5) | (in[3] >> 3)) & 0xfe
	out[4] = ((in[3] << 4) | (in[4] >> 4)) & 0xfe
	out[5] = ((in[4] << 3) | (in[5] >> 5)) & 0xfe
	out[6] = ((in[5] << 2) | (in[6] >> 6)) & 0xfe
	out[7] = in[6] << 1
	out[8] = in[7] & 0xfe
	out[9] = ((in[7] << 7) | (in[8] >> 1)) & 0xfe
	out[10] = ((in[8] << 6) | (in[9] >> 2)) & 0xfe
	out[11] = ((in[9] << 5) | (in[10] >> 3)) & 0xfe
	out[12] = ((in[10] << 4) | (in[11] >> 4)) & 0xfe
	out[13] = ((in[11] << 3) | (in[12] >> 5)) & 0xfe
	out[14] = ((in[12] << 2) | (in[13] >> 6)) & 0xfe
	out[15] = in[13] << 1
	return out
}

func ensureOddParity(b byte) byte {
	if bits.OnesCount8(b)%2 == 0 {
		return b ^ 1
	}
	return b
}

func padMessage(data []byte, length int) (int, error) {
	if length < 3 {
		return 0, fmt.Errorf("newcamd invalid message length")
	}
	padBytes := (8 - ((length - 1) % 8)) % 8
	if length+padBytes+1 >= len(data) {
		return 0, fmt.Errorf("newcamd message buffer too small")
	}

	if padBytes > 0 {
		if _, err := rand.Read(data[length : length+padBytes]); err != nil {
			return 0, fmt.Errorf("newcamd pad random failed: %w", err)
		}
	}
	length += padBytes
	data[length] = xorSum(data[2:length])
	return length + 1, nil
}

func tripleDESEncrypt(block cipher.Block, data []byte, length int) ([]byte, error) {
	if (length-2)%8 != 0 || length < 10 {
		return nil, fmt.Errorf("newcamd bad plaintext length")
	}

	iv := make([]byte, 8)
	if _, err := rand.Read(iv); err != nil {
		return nil, fmt.Errorf("newcamd iv generation failed: %w", err)
	}

	out := make([]byte, length+len(iv))
	copy(out[:2], data[:2])
	encrypter := cipher.NewCBCEncrypter(block, iv)
	encrypter.CryptBlocks(out[2:length], data[2:length])
	copy(out[length:], iv)
	return out, nil
}

func tripleDESDecrypt(block cipher.Block, data []byte) ([]byte, error) {
	if len(data) < 18 {
		return nil, fmt.Errorf("newcamd encrypted message too short")
	}
	encLen := len(data) - 2 - 8
	if encLen <= 0 || encLen%8 != 0 {
		return nil, fmt.Errorf("newcamd encrypted payload length is invalid")
	}

	plain := make([]byte, len(data)-8)
	copy(plain[:2], data[:2])
	iv := make([]byte, 8)
	copy(iv, data[len(data)-8:])

	decrypter := cipher.NewCBCDecrypter(block, iv)
	decrypter.CryptBlocks(plain[2:], data[2:2+encLen])
	return plain, nil
}

func xorSum(mem []byte) byte {
	var cs byte
	for _, b := range mem {
		cs ^= b
	}
	return cs
}
