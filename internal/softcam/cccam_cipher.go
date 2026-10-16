// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

// Each direction owns a separate permutation and plaintext feedback stream.
type cccamCipher struct {
	permutation [256]byte
	position    byte
	accumulator byte
	feedback    byte
}

func newCCcamCipher(key []byte) (*cccamCipher, error) {
	if len(key) == 0 {
		return nil, protocolError("invalid_configuration", nil)
	}
	c := &cccamCipher{feedback: key[0]}
	for index := range c.permutation {
		c.permutation[index] = byte(index)
	}
	var cursor byte
	for index := range c.permutation {
		cursor += c.permutation[index] + key[index%len(key)]
		c.permutation[index], c.permutation[cursor] = c.permutation[cursor], c.permutation[index]
	}
	return c, nil
}

func (c *cccamCipher) mask() byte {
	c.position++
	c.accumulator += c.permutation[c.position]
	c.permutation[c.position], c.permutation[c.accumulator] = c.permutation[c.accumulator], c.permutation[c.position]
	index := c.permutation[c.position] + c.permutation[c.accumulator]
	return c.permutation[index] ^ c.feedback
}

func (c *cccamCipher) encrypt(data []byte) {
	for index, plain := range data {
		data[index] = plain ^ c.mask()
		c.feedback ^= plain
	}
}

func (c *cccamCipher) decrypt(data []byte) {
	for index, ciphertext := range data {
		plain := ciphertext ^ c.mask()
		data[index] = plain
		c.feedback ^= plain
	}
}
