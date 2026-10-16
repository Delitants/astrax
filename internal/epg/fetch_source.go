// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package epg

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
)

var (
	errSourceTooLarge = errors.New("source_too_large")
	errProgrammeLimit = errors.New("programme_limit")
	errXMLDepthLimit  = errors.New("xml_depth_limit")
)

func fetchSource(parent context.Context, client *http.Client, url string, limits FetchLimits) (TV, string, error) {
	ctx, cancel := context.WithTimeout(parent, limits.Timeout)
	defer cancel()
	// The request context owns the complete per-source deadline. Keep injected
	// transports and redirect policy, but do not let New's old timeout cap policy.
	clientCopy := *client
	clientCopy.Timeout = 0
	tv, code, err := readSource(ctx, &clientCopy, url, limits)
	if err == nil {
		// Closing the response or finishing the parse can race with cancellation.
		if err = ctx.Err(); err != nil {
			tv, code = TV{}, "fetch_failed"
		}
	}
	if err != nil {
		var timeout net.Error
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded || (errors.As(err, &timeout) && timeout.Timeout()) {
			return TV{}, "fetch_timeout", errors.New("fetch_timeout")
		}
	}
	return tv, code, err
}

func readSource(ctx context.Context, client *http.Client, url string, limits FetchLimits) (TV, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return TV{}, "fetch_failed", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return TV{}, "fetch_failed", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return TV{}, "fetch_failed", fmt.Errorf("http %d", resp.StatusCode)
	}
	var body io.Reader = resp.Body
	encoded := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip")
	if !encoded && resp.ContentLength > limits.MaxSourceBytes {
		return TV{}, "source_too_large", errSourceTooLarge
	}
	if encoded {
		z, err := gzip.NewReader(resp.Body)
		if err != nil {
			return TV{}, "fetch_failed", err
		}
		defer z.Close()
		body = z
	}
	tv, err := decodeSource(ctx, &sourceByteReader{ctx: ctx, reader: body, remaining: limits.MaxSourceBytes}, limits.MaxProgrammes)
	if err != nil {
		code := "parse_failed"
		switch {
		case errors.Is(err, errSourceTooLarge):
			code = "source_too_large"
		case errors.Is(err, errProgrammeLimit):
			code = "programme_limit"
		case errors.Is(err, errXMLDepthLimit):
			code = "xml_depth_limit"
		}
		return TV{}, code, err
	}
	return tv, "", nil
}

// Probe one extra decompressed byte; EOF at the exact limit is still valid.
type sourceByteReader struct {
	ctx       context.Context
	reader    io.Reader
	remaining int64
}

func (r *sourceByteReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if int64(len(p)) > r.remaining+1 {
		p = p[:r.remaining+1]
	}
	n, err := r.reader.Read(p)
	if contextErr := r.ctx.Err(); contextErr != nil {
		return 0, contextErr
	}
	if int64(n) > r.remaining {
		return 0, errSourceTooLarge
	}
	r.remaining -= int64(n)
	return n, err
}

// DecodeElement and Skip must use the same guard, including unknown descendants.
type sourceTokens struct {
	decoder *xml.Decoder
	ctx     context.Context
	depth   int
}

func (r *sourceTokens) Token() (xml.Token, error) {
	if err := r.ctx.Err(); err != nil {
		return nil, err
	}
	token, err := r.decoder.Token()
	if contextErr := r.ctx.Err(); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, err
	}
	switch token.(type) {
	case xml.StartElement:
		r.depth++
		if r.depth > 64 {
			return nil, errXMLDepthLimit
		}
	case xml.EndElement:
		r.depth--
	}
	return token, nil
}

func decodeSource(ctx context.Context, body io.Reader, maxProgrammes int) (TV, error) {
	guard := &sourceTokens{decoder: xml.NewDecoder(body), ctx: ctx}
	d := xml.NewTokenDecoder(guard)
	var tv TV
	started, ended, declared := false, false, false
	for {
		token, err := d.Token()
		if contextErr := ctx.Err(); contextErr != nil {
			return TV{}, contextErr
		}
		if err == io.EOF {
			if !ended {
				return TV{}, io.ErrUnexpectedEOF
			}
			return tv, nil
		}
		if err != nil {
			return TV{}, err
		}
		switch token := token.(type) {
		case xml.StartElement:
			if ended {
				return TV{}, errors.New("trailing XML element")
			}
			if !started {
				if token.Name.Local != "tv" {
					return TV{}, errors.New("expected XMLTV root")
				}
				started = true
				tv.XMLName = token.Name
				for _, attr := range token.Attr {
					switch attr.Name.Local {
					case "generator-info-name":
						tv.GeneratorInfoName = attr.Value
					case "generator-info-url":
						tv.GeneratorInfoURL = attr.Value
					}
				}
				continue
			}
			switch token.Name.Local {
			case "channel":
				var channel Channel
				if err := d.DecodeElement(&channel, &token); err != nil {
					return TV{}, err
				}
				tv.Channels = append(tv.Channels, channel)
			case "programme":
				if len(tv.Programmes) >= maxProgrammes {
					return TV{}, errProgrammeLimit
				}
				var programme Programme
				if err := d.DecodeElement(&programme, &token); err != nil {
					return TV{}, err
				}
				tv.Programmes = append(tv.Programmes, programme)
			default:
				if err := d.Skip(); err != nil {
					return TV{}, err
				}
			}
		case xml.EndElement:
			ended = true
		case xml.CharData:
			if (!started || ended) && len(bytes.TrimSpace(token)) != 0 {
				return TV{}, errors.New("text outside XMLTV root")
			}
		case xml.ProcInst:
			if strings.EqualFold(token.Target, "xml") {
				if started || declared || token.Target != "xml" {
					return TV{}, errors.New("misplaced XML declaration")
				}
				declared = true
			}
		case xml.Directive:
			if started {
				return TV{}, errors.New("misplaced XML directive")
			}
		}
	}
}
