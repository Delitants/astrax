// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"astrax/internal/model"
)

// Limits count decoded bytes, not characters or URL-escaped bytes. The path
// limit includes its canonical prefix and all separators. JSON counts wire bytes.
const (
	dvbQueryValueLimit = 1024
	dvbSearchLimit     = 256
	dvbPathPartLimit   = 1024
	dvbPathLimit       = 8192
	dvbJSONLimit       = 1 << 20
)

const (
	dvbDescramblingStates  = "waiting_psi waiting_route waiting_keys key_expired partial_clear payload_processed unsupported capacity stopped"
	dvbDescramblingReasons = "stream_stopped policy_disabled catalog_missing catalog_stale input_closed catalog_unavailable no_ca_descriptors unsupported_ca_layout backend_unavailable pipeline_unavailable sink_unavailable unsupported_descrambling_output waiting_keys key_expired partial_clear payload_processed capacity stale_attachment policy_invalid profile_unavailable cipher_failed"
)

type dvbContractError struct {
	Status  int    `json:"-"`
	Code    string `json:"code"`
	Message string `json:"message"`
	Field   string `json:"field,omitempty"`
}

func (e *dvbContractError) Error() string { return e.Message }

func writeDVBError(w http.ResponseWriter, status int, code, message, field string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Error dvbContractError `json:"error"`
	}{
		Error: dvbContractError{Code: code, Message: message, Field: field},
	})
}

func dvbQueryError(field string) error {
	return &dvbContractError{Status: http.StatusBadRequest, Code: "invalid_query", Message: "Invalid query parameter", Field: field}
}

// Copy values so canonicalization never mutates a caller's query map. Sorting
// keys makes field selection deterministic when several parameters are invalid.
func dvbQueryValues(values url.Values, allowed string) (map[string]string, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	out := make(map[string]string, len(values))
	for _, key := range keys {
		entries := values[key]
		if !slices.Contains(strings.Fields(allowed), key) {
			return nil, dvbQueryError("query")
		}
		if len(entries) != 1 {
			return nil, dvbQueryError(key)
		}
		limit := dvbQueryValueLimit
		if key == "q" {
			limit = dvbSearchLimit
		}
		if len(entries[0]) > limit {
			return nil, dvbQueryError(key)
		}
		out[key] = entries[0]
	}
	return out, nil
}

func dvbPositiveInt(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(value)
	return n, err == nil && n > 0
}

func dvbPagination(values map[string]string) (page, limit int, err error) {
	page, limit = 1, 100
	if value, present := values["page"]; present {
		var ok bool
		page, ok = dvbPositiveInt(value)
		if !ok {
			return 0, 0, dvbQueryError("page")
		}
	}
	if value, present := values["limit"]; present {
		var ok bool
		limit, ok = dvbPositiveInt(value)
		if !ok || (limit != 50 && limit != 100 && limit != 200) {
			return 0, 0, dvbQueryError("limit")
		}
	}
	if page-1 > int(^uint(0)>>1)/limit {
		return 0, 0, dvbQueryError("page")
	}
	return page, limit, nil
}

func dvbQueryEnum(values map[string]string, field, allowed, fallback string) error {
	value, present := values[field]
	if !present {
		values[field] = fallback
		return nil
	}
	value = strings.ToLower(strings.TrimSpace(value))
	if !slices.Contains(strings.Fields(allowed), value) {
		return dvbQueryError(field)
	}
	values[field] = value
	return nil
}

func dvbQueryDelivery(values map[string]string, canonicalize func(string) (string, bool)) error {
	if value, present := values["delivery_system"]; present {
		canonical, ok := canonicalize(value)
		if !ok {
			return dvbQueryError("delivery_system")
		}
		values["delivery_system"] = canonical
	}
	return nil
}

func parseDVBCardQuery(values url.Values) (model.DVBCardQuery, error) {
	var query model.DVBCardQuery
	v, err := dvbQueryValues(values, "page limit status delivery_system model q sort order")
	if err != nil {
		return query, err
	}
	page, limit, err := dvbPagination(v)
	if err != nil {
		return query, err
	}
	for _, spec := range [][3]string{
		{"status", "available active busy_external error offline disabled restarting", ""},
		{"sort", "adapter frontend address type id device_key model manufacturer status alias updated_at", "address"},
		{"order", "asc desc", "asc"},
	} {
		if err := dvbQueryEnum(v, spec[0], spec[1], spec[2]); err != nil {
			return query, err
		}
	}
	if err := dvbQueryDelivery(v, model.CanonicalDVBInventoryDeliverySystem); err != nil {
		return query, err
	}
	return model.DVBCardQuery{Page: page, Limit: limit, Status: v["status"], DeliverySystem: v["delivery_system"], Model: v["model"], Q: v["q"], Sort: v["sort"], Order: v["order"]}, nil
}

func parseDVBStreamQuery(values url.Values) (model.DVBStreamQuery, error) {
	var query model.DVBStreamQuery
	v, err := dvbQueryValues(values, "page limit group status requested_adapter actual_adapter delivery_system protocol q sort order descrambling_state descrambling_reason")
	if err != nil {
		return query, err
	}
	page, limit, err := dvbPagination(v)
	if err != nil {
		return query, err
	}
	for _, spec := range [][3]string{
		{"status", "starting tuning on-demand stopped error running locked", ""},
		{"descrambling_state", dvbDescramblingStates, ""},
		{"descrambling_reason", dvbDescramblingReasons, ""},
		{"protocol", "mpegts mpegts-secure udp srt hls hls-secure http rtsp rtsp-secure dvb", ""},
		{"sort", "id status state group group_id service service_id transponder frequency frequency_khz requested_adapter actual_adapter output output_url protocol updated updated_at updated_time name", "name"},
		{"order", "asc desc", "asc"},
	} {
		if err := dvbQueryEnum(v, spec[0], spec[1], spec[2]); err != nil {
			return query, err
		}
	}
	if err := dvbQueryDelivery(v, model.CanonicalDVBDeliverySystem); err != nil {
		return query, err
	}
	for _, field := range []string{"requested_adapter", "actual_adapter"} {
		if value, present := v[field]; present && value == "" {
			return query, dvbQueryError(field)
		}
	}
	// Store reserves "ungrouped" (case-insensitive); its empty Group means ALL.
	// Every other identity is opaque: no trimming, lowercasing, or URL decoding.
	if group, present := v["group"]; present && (group == "" || strings.EqualFold(group, "ungrouped")) {
		v["group"] = "ungrouped"
	}
	return model.DVBStreamQuery{Page: page, Limit: limit, Group: v["group"], Status: v["status"], RequestedAdapter: v["requested_adapter"], ActualAdapter: v["actual_adapter"], DeliverySystem: v["delivery_system"], Protocol: v["protocol"], Q: v["q"], Sort: v["sort"], Order: v["order"], DescramblingState: v["descrambling_state"], DescramblingReason: v["descrambling_reason"]}, nil
}

func decodeDVBJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, dvbJSONLimit)
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(r.Header.Values("Content-Type")) != 1 {
		return &dvbContractError{Status: http.StatusUnsupportedMediaType, Code: "unsupported_media_type", Message: "Content-Type must be application/json"}
	}
	invalid := &dvbContractError{Status: http.StatusBadRequest, Code: "invalid_json", Message: "Expected exactly one valid JSON object with known fields"}
	if r.Body == nil {
		return invalid
	}
	// Read the bounded body first so size errors win even for malformed JSON;
	// the decoder then uses actual destination types, never a lossy generic map.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			return &dvbContractError{Status: http.StatusRequestEntityTooLarge, Code: "body_too_large", Message: "JSON body exceeds 1 MiB"}
		}
		return invalid
	}
	body = bytes.Trim(body, " \t\r\n")
	if len(body) == 0 || body[0] != '{' {
		return invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return invalid
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return invalid
	}
	return nil
}

func dvbPathParts(r *http.Request, prefix string) ([]string, error) {
	invalid := &dvbContractError{Status: http.StatusBadRequest, Code: "invalid_path", Message: "Invalid resource path", Field: "path"}
	if r.URL == nil || len(r.URL.Path) > dvbPathLimit {
		return nil, invalid
	}
	// EscapedPath silently ignores invalid RawPath. Reject it rather than
	// accepting a different identity via that fallback in synthetic requests.
	if r.URL.RawPath != "" {
		decoded, err := url.PathUnescape(r.URL.RawPath)
		if err != nil || decoded != r.URL.Path {
			return nil, invalid
		}
	}
	path := r.URL.EscapedPath()
	if path == prefix {
		return nil, nil
	}
	if !strings.HasPrefix(path, prefix+"/") {
		return nil, invalid
	}
	parts := strings.Split(path[len(prefix)+1:], "/")
	for i, part := range parts {
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." || len(decoded) > dvbPathPartLimit || !utf8.ValidString(decoded) {
			return nil, invalid
		}
		for _, char := range decoded {
			if unicode.IsControl(char) {
				return nil, invalid
			}
		}
		parts[i] = decoded
	}
	return parts, nil
}

// This is a mutation CSRF boundary, not authentication or network access
// control. Callers choose which methods/routes use it; no proxy trust or CORS.
func requireDVBMutationOrigin(r *http.Request) error {
	invalid := &dvbContractError{Status: http.StatusForbidden, Code: "invalid_origin", Message: "Mutation requires same-origin request evidence"}
	if values, present := r.Header[http.CanonicalHeaderKey("Sec-Fetch-Site")]; present {
		if len(values) != 1 || !slices.Contains([]string{"same-origin", "same-site", "none"}, values[0]) {
			return invalid
		}
	}
	origins, present := r.Header["Origin"]
	if !present {
		if r.Context().Value(managementRefererVerifiedKey{}) == true {
			return nil
		}
		marker := r.Header.Values("X-AstraX-Request")
		if len(marker) != 1 || marker[0] != "1" {
			return invalid
		}
		return nil
	}
	if len(origins) != 1 {
		return invalid
	}
	scheme, host, port, ok := dvbOriginTuple(origins[0])
	if !ok {
		return invalid
	}
	wantScheme := "http"
	if r.TLS != nil {
		wantScheme = "https"
	}
	_, wantHost, wantPort, ok := dvbOriginTuple(wantScheme + "://" + r.Host)
	if !ok || scheme != wantScheme || host != wantHost || port != wantPort {
		return invalid
	}
	return nil
}

func dvbOriginTuple(raw string) (scheme, host string, port int, ok bool) {
	if strings.ContainsAny(raw, "?#") {
		return
	}
	for _, c := range raw {
		if unicode.IsSpace(c) || unicode.IsControl(c) {
			return
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Host == "" || u.Path != "" || (u.Scheme != "http" && u.Scheme != "https") {
		return
	}
	scheme, host = u.Scheme, strings.ToLower(u.Hostname())
	if host == "" {
		return
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is6() || ip.Zone() != "" {
			return scheme, host, 0, false
		}
		host = ip.String()
	} else {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
				return scheme, host, 0, false
			}
		}
	}
	port = 80
	if scheme == "https" {
		port = 443
	}
	if explicit := u.Port(); explicit != "" {
		n, valid := dvbPositiveInt(explicit)
		if !valid || n > 65535 {
			return scheme, host, 0, false
		}
		port = n
	} else if strings.HasSuffix(u.Host, ":") {
		return scheme, host, 0, false
	}
	return scheme, host, port, true
}
