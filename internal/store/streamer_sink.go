// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"errors"
	"fmt"

	"astrax/internal/model"
	"astrax/internal/packetbudget"
	"astrax/internal/streamer"
)

type sinkRegistrationToken struct {
	StreamID   string
	Generation uint64
}

type sinkDetachMode uint8

const (
	sinkDetachRemove sinkDetachMode = iota
	sinkDetachPreservePlaceholder
)

type schedulerStreamSink interface {
	RegisterStream(model.Stream, model.PacketSource, *sinkRegistrationToken) (sinkRegistrationToken, error)
	UnregisterStream(sinkRegistrationToken, sinkDetachMode) (*sinkRegistrationToken, error)
	RemoveStream(sinkRegistrationToken) error
	StreamPackets(string) uint64
}

type storeStreamSink interface {
	schedulerStreamSink
	ReplacePlaceholder(sinkRegistrationToken, model.Stream) (sinkRegistrationToken, error)
}

type streamerSinkAdapter struct {
	streamer *streamer.Streamer
}

var _ storeStreamSink = streamerSinkAdapter{}

func (adapter streamerSinkAdapter) DescramblingPacketBudget() *packetbudget.Budget {
	return adapter.streamer.StageCPacketBudget()
}

func newStreamerSinkAdapter(target *streamer.Streamer) storeStreamSink {
	return streamerSinkAdapter{streamer: target}
}

func (adapter streamerSinkAdapter) RegisterStream(stream model.Stream, source model.PacketSource, expected *sinkRegistrationToken) (sinkRegistrationToken, error) {
	if adapter.streamer == nil {
		return sinkRegistrationToken{}, errors.New("streamer sink adapter has no Streamer")
	}
	var concreteExpected *streamer.RegistrationToken
	if expected != nil {
		concreteExpected = &streamer.RegistrationToken{
			StreamID:   expected.StreamID,
			Generation: expected.Generation,
		}
	}
	registered, err := adapter.streamer.RegisterChecked(stream, source, concreteExpected)
	return sinkRegistrationToken{
		StreamID:   registered.StreamID,
		Generation: registered.Generation,
	}, err
}

func (adapter streamerSinkAdapter) UnregisterStream(token sinkRegistrationToken, mode sinkDetachMode) (*sinkRegistrationToken, error) {
	if adapter.streamer == nil {
		return nil, errors.New("streamer sink adapter has no Streamer")
	}
	var concreteMode streamer.DetachMode
	switch mode {
	case sinkDetachRemove:
		concreteMode = streamer.DetachRemove
	case sinkDetachPreservePlaceholder:
		concreteMode = streamer.DetachPreservePlaceholder
	default:
		return nil, fmt.Errorf("unknown sink detach mode %d", mode)
	}
	result, err := adapter.streamer.UnregisterChecked(streamer.RegistrationToken{
		StreamID:   token.StreamID,
		Generation: token.Generation,
	}, concreteMode)
	if result == nil {
		return nil, err
	}
	return &sinkRegistrationToken{
		StreamID:   result.StreamID,
		Generation: result.Generation,
	}, err
}

func (adapter streamerSinkAdapter) RemoveStream(token sinkRegistrationToken) error {
	if adapter.streamer == nil {
		return errors.New("streamer sink adapter has no Streamer")
	}
	return adapter.streamer.RemoveChecked(streamer.RegistrationToken{
		StreamID:   token.StreamID,
		Generation: token.Generation,
	})
}

func (adapter streamerSinkAdapter) ReplacePlaceholder(token sinkRegistrationToken, stream model.Stream) (sinkRegistrationToken, error) {
	if adapter.streamer == nil {
		return sinkRegistrationToken{}, errors.New("streamer sink adapter has no Streamer")
	}
	replaced, err := adapter.streamer.ReplacePlaceholderChecked(streamer.RegistrationToken{
		StreamID:   token.StreamID,
		Generation: token.Generation,
	}, stream)
	return sinkRegistrationToken{
		StreamID:   replaced.StreamID,
		Generation: replaced.Generation,
	}, err
}

func (adapter streamerSinkAdapter) StreamPackets(id string) uint64 {
	if adapter.streamer == nil {
		return 0
	}
	return adapter.streamer.StreamPackets(id)
}
