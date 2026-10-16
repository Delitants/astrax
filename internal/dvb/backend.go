// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

type SessionOpener interface {
	OpenSession(Config) (Session, error)
}

type SystemSessionOpener struct{}

func (SystemSessionOpener) OpenSession(cfg Config) (Session, error) {
	return OpenSession(cfg)
}
