// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package httpapi

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"astrax/internal/model"
)

type dvbOperationService interface {
	RestartDVBCard(context.Context, string) (model.Operation, error)
	Operation(string) (model.Operation, error)
	StartDVBScan(context.Context, model.DVBScanRequest) (model.Operation, error)
	DVBScan(string) (model.DVBScanResult, error)
	ImportDVBScan(string, model.DVBScanImportRequest) (model.BulkDVBStreamResult, error)
}

type dvbOperationResponse struct {
	model.Operation
	OperationURL string `json:"operation_url,omitempty"`
	ResultURL    string `json:"result_url,omitempty"`
}

func (s *Server) handleDVBScans(w http.ResponseWriter, r *http.Request) {
	parts, ok := dvbRoute(w, r, "/api/v1/dvb-scans")
	if !ok {
		return
	}
	if _, ok := dvbQuery(w, r, false); !ok {
		return
	}
	if len(parts) > 2 || len(parts) == 2 && parts[1] != "import" {
		dvbNotFound(w)
		return
	}
	method := http.MethodPost
	if len(parts) == 1 {
		method = http.MethodGet
	}
	if !dvbGuard(w, r, method) {
		return
	}
	if len(parts) == 0 {
		var in model.DVBScanRequest
		if !dvbDecode(w, r, &in) || !validDVBTransport(w, &in.DVB, true) {
			return
		}
		op, err := s.dvbOps.StartDVBScan(r.Context(), in)
		if err != nil {
			respondDVBError(w, err)
			return
		}
		location := "/api/v1/dvb-scans/" + url.PathEscape(op.ID)
		w.Header().Set("Location", location)
		writeJSON(w, http.StatusAccepted, dvbOperationResponse{Operation: safeDVBOperation(op), ResultURL: location})
		return
	}
	result, err := s.dvbOps.DVBScan(parts[0])
	if err != nil {
		respondDVBError(w, err)
		return
	}
	if result.ID != parts[0] {
		dvbNotFound(w)
		return
	}
	if len(parts) == 1 {
		result.Error = safeDVBStatusError(result.Error)
		writeJSON(w, 200, result)
		return
	}
	var in model.DVBScanImportRequest
	if !dvbDecode(w, r, &in) {
		return
	}
	if len(in.ServiceIDs) == 0 || len(in.ServiceIDs) > maxDVBActionItems {
		dvbInvalid(w, "service_ids", "Select between 1 and 1000 services")
		return
	}
	if strings.TrimSpace(in.OutputTemplate) == "" {
		dvbInvalid(w, "output_template", "Output template is required")
		return
	}
	if !validDVBIdentities(w, [2]string{"group_id", in.GroupID}, [2]string{"softcam_id", in.SoftcamID}, [2]string{"adapter.device_key", in.Adapter.DeviceKey}, [2]string{"adapter.last_address", in.Adapter.LastAddress}) {
		return
	}
	imported, err := s.dvbOps.ImportDVBScan(parts[0], in)
	if err != nil {
		respondDVBError(w, err)
		return
	}
	writeDVBBulkResult(w, imported, nil)
}
