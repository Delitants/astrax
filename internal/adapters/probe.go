// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"
	"fmt"
	"net"
	"runtime"

	"astrax/internal/model"
	"astrax/internal/streamer"
)

type Detector interface {
	DetectRuntime() []model.Adapter
	DetectDVB(context.Context) ([]model.DVBCard, error)
}

type SystemDetector struct{}

func (SystemDetector) DetectRuntime() []model.Adapter {
	return DetectRuntime()
}

func (SystemDetector) DetectDVB(ctx context.Context) ([]model.DVBCard, error) {
	return DetectDVB(ctx)
}

func (SystemDetector) Detect() []model.Adapter {
	return Detect()
}

func Detect() []model.Adapter {
	result := DetectRuntime()
	result = append(result, linuxDVBAdapters()...)
	return result
}

func DetectRuntime() []model.Adapter {
	result := []model.Adapter{
		{
			ID:          "host",
			Type:        "host",
			Description: fmt.Sprintf("Runtime %s/%s", runtime.GOOS, runtime.GOARCH),
			Status:      "active",
			InUse:       true,
			UsageCount:  1,
		},
	}

	result = append(result, networkAdapters()...)
	return result
}

func DetectDVB(ctx context.Context) ([]model.DVBCard, error) {
	return linuxDVBCards(ctx)
}

func legacyAdapterFromCard(card model.DVBCard) model.Adapter {
	inUse := card.Status == "busy_external" || card.Status == "active"
	usageCount := card.ActiveStreams
	if usageCount == 0 && inUse {
		usageCount = 1
	}
	return model.Adapter{
		ID:           "dvb" + card.Address,
		Type:         "dvb",
		Address:      card.Address,
		FrontendType: card.FrontendType,
		Model:        card.Model,
		Description:  fmt.Sprintf("Linux DVB adapter %d frontend %d", card.Adapter, card.Frontend),
		Status:       card.Status,
		InUse:        inUse,
		UsageCount:   usageCount,
	}
}

func networkAdapters() []model.Adapter {
	ifaces, err := net.Interfaces()
	return networkAdaptersFromInterfaces(ifaces, err)
}

func networkAdaptersFromInterfaces(ifaces []net.Interface, err error) []model.Adapter {
	srt := model.Adapter{
		ID:          "srt",
		Type:        "srt",
		Address:     "srt",
		Description: "SRT unavailable in non-CGo build",
		Status:      "unavailable",
	}
	if streamer.SRTAvailable() {
		srt.Description = "SRT runtime support in stream engine"
		srt.Status = "active"
		srt.InUse = true
		srt.UsageCount = 1
	}

	if err != nil {
		return []model.Adapter{{
			ID:          "udp",
			Type:        "udp",
			Description: "Unable to inspect network interfaces",
			Status:      "idle",
		}, srt}
	}

	total := 0
	active := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		total++
		if iface.Flags&net.FlagUp != 0 {
			active++
		}
	}

	status := "idle"
	if active > 0 {
		status = "active"
	}

	return []model.Adapter{
		{
			ID:          "udp",
			Type:        "udp",
			Address:     "udp",
			Description: fmt.Sprintf("Network interfaces up: %d/%d", active, total),
			Status:      status,
			InUse:       active > 0,
			UsageCount:  active,
		},
		srt,
	}
}
