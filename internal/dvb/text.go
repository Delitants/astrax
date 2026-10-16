// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"bytes"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// decodeDVBText interprets a DVB-encoded text string according to ETSI EN 300 468.
// DVB strings begin with an optional control byte that indicates the encoding.
func decodeDVBText(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	b := raw[0]
	if b >= 0x20 {
		// No control byte; default encoding is ISO 8859-1 (Latin-1).
		return iso8859ToUTF8(raw, charmap.ISO8859_1)
	}

	switch b {
	case 0x01:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_5)
	case 0x02:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_6)
	case 0x03:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_7)
	case 0x04:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_8)
	case 0x05:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_9)
	case 0x06:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_10)
	case 0x07:
		// Thai TIS-620 / ISO 8859-11 — not available in charmap package;
		// fall back to ISO-8859-1 (rare for DVB names anyway).
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_1)
	case 0x09:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_13)
	case 0x0A:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_14)
	case 0x0B:
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_15)
	case 0x10:
		if len(raw) > 2 {
			part := raw[2]
			switch part {
			case 0x01:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_1)
			case 0x02:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_2)
			case 0x03:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_3)
			case 0x04:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_4)
			case 0x05:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_5)
			case 0x06:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_6)
			case 0x07:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_7)
			case 0x08:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_8)
			case 0x09:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_9)
			case 0x0A:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_10)
			case 0x0B:
				// ISO 8859-11 not in charmap; fall back to ISO-8859-1.
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_1)
			default:
				return iso8859ToUTF8(raw[3:], charmap.ISO8859_1)
			}
		}
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_1)
	case 0x11:
		// UCS-2 (UTF-16 BE) - two-byte characters
		if len(raw) > 1 {
			return decodeUCS2(raw[1:])
		}
	case 0x15:
		// UTF-8
		s := string(raw[1:])
		if utf8.ValidString(s) {
			return s
		}
		return sanitizeInvalidUTF8(raw[1:])
	default:
		// Unknown control byte: strip it and treat remainder as ISO-8859-1.
		return iso8859ToUTF8(raw[1:], charmap.ISO8859_1)
	}
	return ""
}

func iso8859ToUTF8(b []byte, dec *charmap.Charmap) string {
	if len(b) == 0 {
		return ""
	}
	result, err := dec.NewDecoder().String(string(b))
	if err != nil {
		// On decode error, fall back to a safe byte-by-byte pass.
		return sanitizeInvalidUTF8(b)
	}
	return result
}

func decodeUCS2(b []byte) string {
	var out bytes.Buffer
	out.Grow(len(b) / 2)
	for i := 0; i+1 < len(b); i += 2 {
		r := rune((uint16(b[i]) << 8) | uint16(b[i+1]))
		if r == 0 {
			break
		}
		if utf8.ValidRune(r) {
			out.WriteRune(r)
		}
	}
	return out.String()
}

func sanitizeInvalidUTF8(b []byte) string {
	var out bytes.Buffer
	out.Grow(len(b))
	for _, c := range string(b) {
		if c == utf8.RuneError {
			out.WriteRune('?')
		} else {
			out.WriteRune(c)
		}
	}
	return out.String()
}

// sanitizeDVBText is a convenience wrapper that accepts a Go string
// created from raw bytes (as the old code did) and re-decodes it properly.
func sanitizeDVBText(s string) string {
	return decodeDVBText([]byte(s))
}
