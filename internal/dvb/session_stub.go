//go:build !linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import "fmt"

type unsupportedSession struct{}

func OpenSession(cfg Config) (Session, error) {
	_ = cfg
	return nil, fmt.Errorf("linux dvb frontend support requires a linux build")
}

func (s *unsupportedSession) Poll() (Signal, error) {
	return Signal{}, fmt.Errorf("linux dvb frontend support requires a linux build")
}

func (s *unsupportedSession) ScanServices() ([]Service, error) {
	return nil, fmt.Errorf("linux dvb frontend support requires a linux build")
}

func (s *unsupportedSession) Close() error {
	return nil
}

func (s *unsupportedSession) OpenDemux(videoPID, audioPID, pcrPID int) (DemuxReader, error) {
	return nil, fmt.Errorf("linux dvb demux support requires a linux build")
}

func (s *unsupportedSession) DemuxPath() string {
	return ""
}

type unsupportedDemuxReader struct{}

func (s *unsupportedDemuxReader) ReadPacket() ([]byte, error) {
	return nil, fmt.Errorf("linux dvb demux support requires a linux build")
}

func (s *unsupportedDemuxReader) Close() error {
	return nil
}
