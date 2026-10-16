// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

const (
	hlsSegmentDuration = 2 * time.Second
	hlsWindowSize      = 6
)

type hlsSegment struct {
	index    int
	duration time.Duration
	data     []byte
}

type hlsBuffer struct {
	mu        sync.RWMutex
	bounded   *boundedHLSState
	segments  []hlsSegment
	current   *bytes.Buffer
	startTime time.Time
	index     int
}

func newHLSBuffer() *hlsBuffer {
	return &hlsBuffer{
		current:   &bytes.Buffer{},
		startTime: time.Now(),
	}
}

func (h *hlsBuffer) WritePacket(pkt []byte) {
	if h.bounded != nil {
		_ = h.WritePacketChecked(pkt)
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	// Check if we should finalize the current segment
	if time.Since(h.startTime) >= hlsSegmentDuration && h.current.Len() > 0 {
		duration := time.Since(h.startTime)
		seg := hlsSegment{
			index:    h.index,
			duration: duration,
			data:     append([]byte(nil), h.current.Bytes()...),
		}
		h.segments = append(h.segments, seg)
		if len(h.segments) > hlsWindowSize {
			h.segments = h.segments[len(h.segments)-hlsWindowSize:]
		}
		h.current.Reset()
		h.startTime = time.Now()
		h.index++
	}

	h.current.Write(pkt)
}

func (h *hlsBuffer) Playlist(baseURL string) []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var b bytes.Buffer
	b.WriteString("#EXTM3U\n")
	b.WriteString("#EXT-X-VERSION:3\n")
	b.WriteString("#EXT-X-TARGETDURATION:3\n")
	b.WriteString("#EXT-X-MEDIA-SEQUENCE:")
	if h.bounded != nil {
		return h.boundedPlaylistLocked(nil, baseURL)
	}
	if len(h.segments) > 0 {
		b.WriteString(fmt.Sprintf("%d\n", h.segments[0].index))
	} else {
		b.WriteString("0\n")
	}

	for _, seg := range h.segments {
		durationSec := seg.duration.Seconds()
		if durationSec < 0.1 {
			durationSec = 2.0
		}
		b.WriteString(fmt.Sprintf("#EXTINF:%.3f,\n", durationSec))
		b.WriteString(fmt.Sprintf("%s_%d.ts\n", baseURL, seg.index))
	}

	// Include the active in-flight segment so players can follow live edge
	if h.current.Len() > 0 {
		durationSec := time.Since(h.startTime).Seconds()
		if durationSec < 0.1 {
			durationSec = 0.1
		}
		b.WriteString(fmt.Sprintf("#EXTINF:%.3f,\n", durationSec))
		b.WriteString(fmt.Sprintf("%s_%d.ts\n", baseURL, h.index))
	}

	return b.Bytes()
}

func (h *hlsBuffer) Segment(index int) ([]byte, bool) {
	// Stage C consumers must hold an explicit response lease, not borrow data.
	if h.bounded != nil {
		return nil, false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, seg := range h.segments {
		if seg.index == index {
			return seg.data, true
		}
	}

	// If requesting the current in-flight segment
	if index == h.index && h.current.Len() > 0 {
		return append([]byte(nil), h.current.Bytes()...), true
	}

	return nil, false
}

func (h *hlsBuffer) boundedPlaylistLocked(dst []byte, baseURL string) []byte {
	b := h.bounded
	first := h.index
	if len(b.completed) > 0 {
		first = b.completed[0].index
	}
	dst = fmt.Appendf(dst, "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:3\n#EXT-X-MEDIA-SEQUENCE:%d\n", first)
	if b.discontinuitySequence != 0 {
		dst = fmt.Appendf(dst, "#EXT-X-DISCONTINUITY-SEQUENCE:%d\n", b.discontinuitySequence)
	}
	for _, segment := range b.completed {
		if segment.discontinuity {
			dst = append(dst, "#EXT-X-DISCONTINUITY\n"...)
		}
		dst = fmt.Appendf(dst, "#EXTINF:%.3f,\n%s_%d.ts\n", segment.duration.Seconds(), baseURL, segment.index)
	}
	if !b.closed && !b.discard && b.active != nil && len(b.active.data) > 0 {
		if b.activeDiscontinuity {
			dst = append(dst, "#EXT-X-DISCONTINUITY\n"...)
		}
		duration := max(0.1, b.now().Sub(h.startTime).Seconds())
		dst = fmt.Appendf(dst, "#EXTINF:%.3f,\n%s_%d.ts\n", duration, baseURL, h.index)
	} else if b.pendingDiscontinuity {
		// Keep explicit discard status without tagging a retained pre-gap
		// segment or publishing an incomplete URI. Recovery owns this tag.
		dst = append(dst, "#EXT-X-DISCONTINUITY\n"...)
	}
	return dst
}
