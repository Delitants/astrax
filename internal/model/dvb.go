// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const CurrentSchemaVersion = 2

type DVBGroup struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type DVBCardConfig struct {
	DeviceKey   string                `json:"device_key"`
	LastAddress string                `json:"last_address,omitempty"`
	Alias       string                `json:"alias,omitempty"`
	Enabled     bool                  `json:"enabled"`
	RFDefaults  AdapterLNBConfig      `json:"rf_defaults"`
	Advanced    AdapterAdvancedConfig `json:"advanced"`
	UpdatedAt   time.Time             `json:"updated_at"`
}

// DVBCardApplication describes scheduler acceptance, not successful tuning.
// This state is runtime-only; Config remains the durable desired configuration.
type DVBCardApplication struct {
	// Zero while durable desired settings await scheduler publication.
	DesiredRevision   uint64         `json:"desired_revision"`
	SelectionRevision uint64         `json:"selection_revision"`
	AppliedConfig     *DVBCardConfig `json:"applied_config,omitempty"`
	State             string         `json:"state"`
	AdmissionBlocked  bool           `json:"admission_blocked"`
	Reason            string         `json:"reason,omitempty"`
	Error             string         `json:"error,omitempty"`
}

type DVBCard struct {
	Application      *DVBCardApplication `json:"application,omitempty"`
	ID               string              `json:"id"`
	DeviceKey        string              `json:"device_key"`
	Address          string              `json:"address"`
	Adapter          int                 `json:"adapter"`
	Frontend         int                 `json:"frontend"`
	FrontendType     string              `json:"frontend_type,omitempty"`
	DeliverySystems  []string            `json:"delivery_systems,omitempty"`
	Manufacturer     string              `json:"manufacturer,omitempty"`
	Model            string              `json:"model,omitempty"`
	SysfsPath        string              `json:"sysfs_path,omitempty"`
	DevicePath       string              `json:"device_path,omitempty"`
	Present          bool                `json:"present"`
	Status           string              `json:"status"`
	OwnerPID         int                 `json:"owner_pid,omitempty"`
	OwnerCommand     string              `json:"owner_command,omitempty"`
	CurrentTransport *DVBStreamConfig    `json:"current_transport,omitempty"`
	ActiveSessions   int                 `json:"active_sessions"`
	ActiveStreams    int                 `json:"active_streams"`
	Signal           *DVBSignal          `json:"signal,omitempty"`
	Config           DVBCardConfig       `json:"config"`
	Warning          string              `json:"warning,omitempty"`
	LastError        string              `json:"last_error,omitempty"`
	UpdatedAt        time.Time           `json:"updated_at"`
}

type DVBCardQuery struct {
	Status         string `json:"status,omitempty"`
	DeliverySystem string `json:"delivery_system,omitempty"`
	Model          string `json:"model,omitempty"`
	Q              string `json:"q,omitempty"`
	Sort           string `json:"sort,omitempty"`
	Order          string `json:"order,omitempty"`
	Page           int    `json:"page,omitempty"`
	Limit          int    `json:"limit,omitempty"`
}

type DVBCardPage struct {
	Items        []DVBCard      `json:"items"`
	Total        int            `json:"total"`
	Page         int            `json:"page,omitempty"`
	Limit        int            `json:"limit,omitempty"`
	Summary      DVBCardSummary `json:"summary"`
	RefreshedAt  time.Time      `json:"refreshed_at"`
	RefreshError string         `json:"refresh_error"`
	Stale        bool           `json:"stale"`
	Facets       DVBCardFacets  `json:"facets"`
}

// Facets describe the whole inventory, independently of filters and pagination.
type DVBCardFacets struct {
	Models          []string `json:"models"`
	DeliverySystems []string `json:"delivery_systems"`
}

type DVBCardSummary struct {
	Total        int `json:"total"`
	Available    int `json:"available"`
	Active       int `json:"active"`
	BusyExternal int `json:"busy_external"`
	Error        int `json:"error"`
	Offline      int `json:"offline"`
	Disabled     int `json:"disabled"`
}

type DVBAdapterPolicy struct {
	Mode        string `json:"mode"`
	DeviceKey   string `json:"device_key,omitempty"`
	LastAddress string `json:"last_address,omitempty"`
}

type DVBStreamConfig struct {
	Service        *Service              `json:"service,omitempty"`
	DeliverySystem string                `json:"delivery_system"`
	FrequencyKHz   uint32                `json:"frequency_khz"`
	SymbolRate     uint32                `json:"symbol_rate,omitempty"`
	Polarization   string                `json:"polarization,omitempty"`
	Modulation     string                `json:"modulation,omitempty"`
	FEC            string                `json:"fec,omitempty"`
	RollOff        string                `json:"rolloff,omitempty"`
	StreamID       string                `json:"stream_id,omitempty"`
	ServiceID      int                   `json:"service_id"`
	VideoPID       int                   `json:"video_pid,omitempty"`
	AudioPIDs      []int                 `json:"audio_pids,omitempty"`
	PCRPID         int                   `json:"pcr_pid,omitempty"`
	RFOverride     *AdapterLNBConfig     `json:"rf_override,omitempty"`
	Advanced       AdapterAdvancedConfig `json:"advanced"`
	Adapter        DVBAdapterPolicy      `json:"adapter"`
}

// CanonicalDVBDeliverySystem accepts only canonical DVB delivery tokens and
// their standard single-hyphen aliases.
func CanonicalDVBDeliverySystem(value string) (string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "dvbs", "dvb-s":
		return "dvbs", true
	case "dvbs2", "dvb-s2":
		return "dvbs2", true
	case "dvbc", "dvb-c":
		return "dvbc", true
	case "dvbt", "dvb-t":
		return "dvbt", true
	case "dvbt2", "dvb-t2":
		return "dvbt2", true
	default:
		return value, false
	}
}

// CanonicalDVBInventoryDeliverySystem describes detected capabilities, not
// supported tuning modes. Keep inventory-only systems out of tuning validation.
func CanonicalDVBInventoryDeliverySystem(value string) (string, bool) {
	value, ok := CanonicalDVBDeliverySystem(value)
	if ok {
		return value, true
	}
	switch value {
	case "atsc":
		return "atsc", true
	case "isdbt", "isdb-t":
		return "isdbt", true
	default:
		return value, false
	}
}

func (c *DVBStreamConfig) Normalize() {
	if c == nil {
		return
	}
	delivery, _ := CanonicalDVBDeliverySystem(c.DeliverySystem)
	c.DeliverySystem = delivery
	polarization := strings.ToUpper(strings.TrimSpace(c.Polarization))
	switch polarization {
	case "HORIZONTAL":
		polarization = "H"
	case "VERTICAL":
		polarization = "V"
	}
	c.Polarization = polarization
	c.Adapter.Mode = strings.ToLower(strings.TrimSpace(c.Adapter.Mode))
	if c.Adapter.Mode == "" {
		c.Adapter.Mode = "auto"
	}
	c.Adapter.DeviceKey = strings.TrimSpace(c.Adapter.DeviceKey)
	c.Adapter.LastAddress = strings.TrimSpace(c.Adapter.LastAddress)
}

func (c DVBStreamConfig) Validate() error {
	if c.FrequencyKHz == 0 {
		return errors.New("frequency_khz must be greater than zero")
	}
	switch c.DeliverySystem {
	case "dvbs", "dvbs2":
		if c.SymbolRate == 0 {
			return errors.New("symbol_rate must be greater than zero")
		}
		if c.Polarization != "H" && c.Polarization != "V" {
			return errors.New("polarization must be H or V")
		}
	case "dvbc", "dvbt", "dvbt2":
	default:
		return fmt.Errorf("unsupported delivery_system %q", c.DeliverySystem)
	}
	if c.ServiceID < 1 || c.ServiceID > 0xffff {
		return errors.New("service_id must be between 1 and 65535")
	}
	if c.Adapter.Mode != "auto" && c.Adapter.Mode != "fixed" {
		return errors.New("adapter mode must be auto or fixed")
	}
	if c.Adapter.Mode == "fixed" && c.Adapter.DeviceKey == "" && c.Adapter.LastAddress == "" {
		return errors.New("fixed adapter requires device_key")
	}
	for _, pid := range append([]int{c.VideoPID, c.PCRPID}, c.AudioPIDs...) {
		if pid < 0 || pid > 0x1fff {
			return fmt.Errorf("PID %d is outside the 13-bit MPEG-TS range", pid)
		}
	}
	return nil
}

type DVBPlacementRuntime struct {
	RequestedMode   string `json:"requested_mode"`
	RequestedCardID string `json:"requested_card_id,omitempty"`
	ActualCardID    string `json:"actual_card_id,omitempty"`
	ActualAddress   string `json:"actual_address,omitempty"`
	TuningSessionID string `json:"tuning_session_id,omitempty"`
}

type DVBStreamQuery struct {
	DescramblingState  string `json:"descrambling_state,omitempty"`
	DescramblingReason string `json:"descrambling_reason,omitempty"`
	Page               int    `json:"page,omitempty"`
	Limit              int    `json:"limit,omitempty"`
	Group              string `json:"group,omitempty"`
	Status             string `json:"status,omitempty"`
	RequestedAdapter   string `json:"requested_adapter,omitempty"`
	ActualAdapter      string `json:"actual_adapter,omitempty"`
	DeliverySystem     string `json:"delivery_system,omitempty"`
	Protocol           string `json:"protocol,omitempty"`
	Q                  string `json:"q,omitempty"`
	Sort               string `json:"sort,omitempty"`
	Order              string `json:"order,omitempty"`
}

type DVBStreamFacets struct {
	Groups            map[string]int `json:"groups,omitempty"`
	Statuses          map[string]int `json:"statuses,omitempty"`
	RequestedAdapters map[string]int `json:"requested_adapters,omitempty"`
	ActualAdapters    map[string]int `json:"actual_adapters,omitempty"`
	DeliverySystems   map[string]int `json:"delivery_systems,omitempty"`
	Protocols         map[string]int `json:"protocols,omitempty"`
}

type DVBStreamPage struct {
	Items  []Stream        `json:"items"`
	Total  int             `json:"total"`
	Page   int             `json:"page"`
	Limit  int             `json:"limit"`
	Facets DVBStreamFacets `json:"facets"`
}

type BulkDVBStreamRequest struct {
	Action  string            `json:"action"`
	IDs     []string          `json:"ids"`
	GroupID string            `json:"group_id,omitempty"`
	Adapter *DVBAdapterPolicy `json:"adapter,omitempty"`
}

type BulkDVBStreamItemResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type BulkDVBStreamResult struct {
	Results   []BulkDVBStreamItemResult `json:"results"`
	Succeeded int                       `json:"succeeded"`
	Failed    int                       `json:"failed"`
}

type DVBScanRequest struct {
	DVB DVBStreamConfig `json:"dvb"`
}

type DVBScanResult struct {
	ID          string         `json:"id"`
	OperationID string         `json:"operation_id,omitempty"`
	Status      string         `json:"status"`
	Request     DVBScanRequest `json:"request"`
	CardID      string         `json:"card_id,omitempty"`
	Address     string         `json:"address,omitempty"`
	Signal      *DVBSignal     `json:"signal,omitempty"`
	Services    []Service      `json:"services,omitempty"`
	Error       string         `json:"error,omitempty"`
	StartedAt   time.Time      `json:"started_at"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
}

type DVBScanImportRequest struct {
	ServiceIDs             []int            `json:"service_ids"`
	GroupID                string           `json:"group_id,omitempty"`
	Adapter                DVBAdapterPolicy `json:"adapter"`
	NameTemplate           string           `json:"name_template,omitempty"`
	OutputTemplate         string           `json:"output_template"`
	Protocol               string           `json:"protocol,omitempty"`
	SoftcamID              string           `json:"softcam_id,omitempty"`
	XMLTVChannelIDTemplate string           `json:"xmltv_channel_id_template,omitempty"`
	Enabled                bool             `json:"enabled"`
}

type Operation struct {
	ID            string                    `json:"id"`
	Kind          string                    `json:"kind"`
	ResourceID    string                    `json:"resource_id,omitempty"`
	Status        string                    `json:"status"`
	Progress      int                       `json:"progress,omitempty"`
	Message       string                    `json:"message,omitempty"`
	Error         string                    `json:"error,omitempty"`
	StreamResults []BulkDVBStreamItemResult `json:"stream_results,omitempty"`
	Result        any                       `json:"result,omitempty"`
	CreatedAt     time.Time                 `json:"created_at"`
	UpdatedAt     time.Time                 `json:"updated_at"`
	CompletedAt   *time.Time                `json:"completed_at,omitempty"`
}

type ResourceEvent struct {
	ID         uint64    `json:"id"`
	Kind       string    `json:"kind"`
	ResourceID string    `json:"resource_id,omitempty"`
	Revision   uint64    `json:"revision"`
	Payload    any       `json:"payload,omitempty"`
	At         time.Time `json:"at"`
}
