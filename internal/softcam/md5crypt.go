// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"crypto/md5"
	"fmt"
	"strings"
)

const md5CryptMagic = "$1$"

var itoa64 = []byte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

// md5Crypt returns a password hash compatible with crypt(3) MD5 ($1$) output.
func md5Crypt(password, salt string) (string, error) {
	salt = sanitizeMD5Salt(salt)
	if salt == "" {
		return "", fmt.Errorf("md5crypt salt is empty")
	}

	ctx := md5.New()
	ctx.Write([]byte(password))
	ctx.Write([]byte(md5CryptMagic))
	ctx.Write([]byte(salt))

	alt := md5.New()
	alt.Write([]byte(password))
	alt.Write([]byte(salt))
	alt.Write([]byte(password))
	altSum := alt.Sum(nil)

	for n := len(password); n > 0; n -= 16 {
		limit := 16
		if n < 16 {
			limit = n
		}
		ctx.Write(altSum[:limit])
	}

	for n := len(password); n > 0; n >>= 1 {
		if n&1 == 1 {
			ctx.Write([]byte{0x00})
		} else {
			ctx.Write([]byte{password[0]})
		}
	}

	sum := ctx.Sum(nil)
	for i := 0; i < 1000; i++ {
		round := md5.New()
		if i&1 == 1 {
			round.Write([]byte(password))
		} else {
			round.Write(sum)
		}
		if i%3 != 0 {
			round.Write([]byte(salt))
		}
		if i%7 != 0 {
			round.Write([]byte(password))
		}
		if i&1 == 1 {
			round.Write(sum)
		} else {
			round.Write([]byte(password))
		}
		sum = round.Sum(nil)
	}

	encoded := make([]byte, 0, 22)
	encoded = append(encoded, b64From24(sum[0], sum[6], sum[12], 4)...)
	encoded = append(encoded, b64From24(sum[1], sum[7], sum[13], 4)...)
	encoded = append(encoded, b64From24(sum[2], sum[8], sum[14], 4)...)
	encoded = append(encoded, b64From24(sum[3], sum[9], sum[15], 4)...)
	encoded = append(encoded, b64From24(sum[4], sum[10], sum[5], 4)...)
	encoded = append(encoded, b64From24(0x00, 0x00, sum[11], 2)...)

	return md5CryptMagic + salt + "$" + string(encoded), nil
}

func sanitizeMD5Salt(salt string) string {
	if strings.HasPrefix(salt, md5CryptMagic) {
		salt = strings.TrimPrefix(salt, md5CryptMagic)
	}
	if idx := strings.IndexByte(salt, '$'); idx >= 0 {
		salt = salt[:idx]
	}
	if len(salt) > 8 {
		salt = salt[:8]
	}
	return salt
}

func b64From24(b2, b1, b0 byte, count int) []byte {
	value := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	out := make([]byte, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, itoa64[value&0x3f])
		value >>= 6
	}
	return out
}
