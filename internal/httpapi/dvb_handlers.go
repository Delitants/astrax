// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"astrax/internal/model"
	"astrax/internal/store"
	"astrax/internal/streamer"
)

const maxDVBActionItems = 1000

func dvbGuard(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	if r.Context().Err() != nil {
		return false
	}
	if !slices.Contains(methods, r.Method) {
		w.Header().Set("Allow", strings.Join(methods, ", "))
		writeDVBError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed", "")
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		if _, authenticated := externalPrincipal(r); authenticated {
			return true
		}
		if err := requireDVBMutationOrigin(r); err != nil {
			respondDVBError(w, err)
			return false
		}
	}
	return true
}

func dvbRoute(w http.ResponseWriter, r *http.Request, prefix string) ([]string, bool) {
	parts, err := dvbPathParts(r, prefix)
	if err != nil {
		respondDVBError(w, err)
		return nil, false
	}
	return parts, true
}

func dvbQuery(w http.ResponseWriter, r *http.Request, allowed bool) (url.Values, bool) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !allowed && len(values) != 0 {
		writeDVBError(w, http.StatusBadRequest, "invalid_query", "Invalid query parameters", "query")
		return nil, false
	}
	return values, true
}

func dvbDecode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := decodeDVBJSON(w, r, dst); err != nil {
		respondDVBError(w, err)
		return false
	}
	return true
}

func dvbActionBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return true
	}
	return dvbDecode(w, r, &struct{}{})
}

func dvbNotFound(w http.ResponseWriter) {
	writeDVBError(w, http.StatusNotFound, "not_found", "DVB resource or action not found", "")
}

func dvbInvalid(w http.ResponseWriter, field, message string) {
	writeDVBError(w, http.StatusBadRequest, "invalid_configuration", message, field)
}

func respondDVBError(w http.ResponseWriter, err error) {
	contract := classifyDVBError(err)
	writeDVBError(w, contract.Status, contract.Code, contract.Message, contract.Field)
}

func classifyDVBError(err error) dvbContractError {
	var contract *dvbContractError
	if errors.As(err, &contract) {
		return *contract
	}
	status, code, message, field := http.StatusInternalServerError, "internal_error", "The operation could not be completed", ""
	switch {
	case errors.Is(err, store.ErrDVBStreamNotFound), errors.Is(err, store.ErrDVBCardNotFound), errors.Is(err, store.ErrDVBOperationNotFound):
		status, code, message = 404, "not_found", "DVB resource not found"
	case errors.Is(err, store.ErrCardExternallyBusy):
		status, code, message, field = 409, "card_busy_external", "Frontend is owned by another process", "dvb.adapter.device_key"
	case errors.Is(err, store.ErrNoDVBCardAvailable):
		status, code, message, field = 409, "card_unavailable", "No compatible DVB card is available", "dvb.adapter"
	case errors.Is(err, store.ErrDVBSchedulerOwnership), errors.Is(err, store.ErrDVBOperationsFull):
		status, code, message = 409, "resource_busy", "The resource is busy"
	case errors.Is(err, store.ErrDVBSchedulerSuperseded), errors.Is(err, store.ErrDVBRefreshSuperseded), errors.Is(err, streamer.ErrRegistrationSuperseded):
		status, code, message = 409, "operation_superseded", "A newer change superseded this operation"
	case errors.Is(err, streamer.ErrStreamPathConflict), errors.Is(err, streamer.ErrStreamReserved):
		status, code, message, field = 409, "output_conflict", "The output route is already reserved", "output_url"
	case errors.Is(err, store.ErrStoreClosed), errors.Is(err, store.ErrDVBSchedulerClosed), errors.Is(err, streamer.ErrStreamerClosed):
		status, code, message = 503, "runtime_unavailable", "The runtime is unavailable"
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status, code, message = 408, "operation_cancelled", "The operation was cancelled or timed out"
	default:
		// Compatibility with the existing Store's fixed validation messages.
		// Never return arbitrary persistence/backend errors or interpolate input.
		switch err.Error() {
		case "structured DVB scheduler unavailable":
			status, code, message = 503, "runtime_unavailable", "The DVB runtime is unavailable"
		case "dvb card not found", "DVB stream not found", "stream not found":
			status, code, message = 404, "not_found", "DVB resource not found"
		case "dvb group not found":
			status, code, message, field = 404, "group_not_found", "DVB group not found", "group_id"
		case "softcam not found":
			status, code, message, field = 404, "softcam_not_found", "Softcam profile not found", "softcam_id"
		case "dvb group name already exists":
			status, code, message, field = 409, "group_name_conflict", "A group already has this name", "name"
		case "name is required":
			status, code, message, field = 400, "invalid_configuration", "Name is required", "name"
		case "auto adapter cannot use LastAddress 0.0":
			status, code, message, field = 400, "invalid_configuration", "Auto must not use the fallback address 0.0", "dvb.adapter.last_address"
		case "scan is not ready to import":
			status, code, message = 409, "scan_not_ready", "The scan is not ready to import"
		case "satellite RF requires positive LOF1, LOF2, and SLOF":
			status, code, message, field = 400, "invalid_configuration", "LOF1, LOF2 and SLOF must be positive", "rf_defaults"
		case "Unicable I slot must be between 1 and 8", "Unicable II slot must be between 1 and 32":
			status, code, message, field = 400, "invalid_configuration", "Unicable slot is outside the mode's range", "rf_defaults.unicable_slot"
		case "Unicable I user-band frequency must be positive", "Unicable II user-band frequency must be positive":
			status, code, message, field = 400, "invalid_configuration", "User-band frequency must be positive", "rf_defaults.slot_frequency"
		case "advanced timeout_sec must be non-negative":
			status, code, message, field = 400, "invalid_configuration", "Timeout must be non-negative", "advanced.timeout_sec"
		case "dvb group reorder must contain every group exactly once", "dvb group reorder cannot contain Ungrouped", "dvb group reorder contains a duplicate ID", "dvb group reorder contains an unknown ID":
			status, code, message, field = 400, "invalid_configuration", "Reorder must contain every editable group exactly once", "ids"
		}
		if strings.HasPrefix(err.Error(), "output_url duplicates stream ") || strings.HasPrefix(err.Error(), "output route ") && strings.Contains(err.Error(), " duplicates stream ") {
			status, code, message, field = 409, "output_conflict", "The output route is already configured", "output_url"
		}
	}
	return dvbContractError{Status: status, Code: code, Message: message, Field: field}
}

func writeDVBBulkResult(w http.ResponseWriter, result model.BulkDVBStreamResult, err error) {
	result.Results = slices.Clone(result.Results)
	for i := range result.Results {
		item := &result.Results[i]
		if item.OK {
			item.Error = ""
			continue
		}
		switch item.Error {
		case "Invalid stream ID", "duplicate DVB stream ID in request", "DVB stream not found", "stream is not a structured DVB stream":
		default:
			item.Error = safeDVBStatusError(item.Error)
			if item.Error == "" {
				item.Error = "The operation could not be completed"
			}
		}
	}
	if err == nil {
		writeJSON(w, http.StatusOK, result)
		return
	}
	contract := classifyDVBError(err)
	writeJSON(w, contract.Status, struct {
		model.BulkDVBStreamResult
		Error dvbContractError `json:"error"`
	}{result, contract})
}

func safeDVBStatusError(message string) string {
	if message == "" {
		return ""
	}
	const prefix, suffix = "service ", " not found in scan"
	if strings.HasPrefix(message, prefix) && strings.HasSuffix(message, suffix) {
		number := strings.TrimSuffix(strings.TrimPrefix(message, prefix), suffix)
		if len(number) <= 20 {
			if sid, err := strconv.ParseInt(number, 10, 64); err == nil && strconv.FormatInt(sid, 10) == number {
				return "Service not found in scan"
			}
		}
	}
	return classifyDVBError(errors.New(message)).Message
}

func safeDVBOperation(operation model.Operation) model.Operation {
	operation.Error = safeDVBStatusError(operation.Error)
	operation.StreamResults = slices.Clone(operation.StreamResults)
	for i := range operation.StreamResults {
		operation.StreamResults[i].Error = safeDVBStatusError(operation.StreamResults[i].Error)
	}
	return operation
}

func validDVBTransport(w http.ResponseWriter, cfg *model.DVBStreamConfig, scan bool) bool {
	if cfg == nil {
		dvbInvalid(w, "dvb", "DVB configuration is required")
		return false
	}
	if !validDVBIdentities(w, [2]string{"dvb.adapter.device_key", cfg.Adapter.DeviceKey}, [2]string{"dvb.adapter.last_address", cfg.Adapter.LastAddress}) {
		return false
	}
	cfg.Normalize()
	if _, ok := model.CanonicalDVBDeliverySystem(cfg.DeliverySystem); !ok {
		writeDVBError(w, 422, "unsupported_delivery_system", "Unsupported delivery system", "dvb.delivery_system")
		return false
	}
	validation := *cfg
	if scan && validation.ServiceID == 0 {
		validation.ServiceID = 1
	}
	if err := validation.Validate(); err != nil {
		field := "dvb"
		switch {
		case cfg.FrequencyKHz == 0:
			field = "dvb.frequency_khz"
		case cfg.DeliverySystem == "dvbs" || cfg.DeliverySystem == "dvbs2":
			if cfg.SymbolRate == 0 {
				field = "dvb.symbol_rate"
			} else if cfg.Polarization != "H" && cfg.Polarization != "V" {
				field = "dvb.polarization"
			}
		}
		dvbInvalid(w, field, "Invalid DVB tuning or service configuration")
		return false
	}
	return true
}

func validDVBIdentities(w http.ResponseWriter, fields ...[2]string) bool {
	for _, field := range fields {
		if len(field[1]) > dvbPathPartLimit || strings.TrimSpace(field[1]) != field[1] {
			dvbInvalid(w, field[0], "Invalid resource identifier")
			return false
		}
	}
	return true
}
