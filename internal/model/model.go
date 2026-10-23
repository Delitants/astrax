// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package model

import "time"

const DefaultVersion = "0.1.0-dev"

type Stream struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	InputURL           string                 `json:"input_url"`
	OutputURL          string                 `json:"output_url"`
	Protocol           string                 `json:"protocol"`
	SoftcamID          string                 `json:"softcam_id,omitempty"`
	Enabled            bool                   `json:"enabled"`
	UpdatedAt          time.Time              `json:"updated_at"`
	Runtime            StreamRuntime          `json:"runtime"`
	GroupID            string                 `json:"group_id,omitempty"`
	DVB                *DVBStreamConfig       `json:"dvb,omitempty"`
	DVBDescrambling    *DVBDescramblingConfig `json:"dvb_descrambling,omitempty"`
	AdapterProfileID   string                 `json:"adapter_profile_id,omitempty"`
	Scrambled          bool                   `json:"scrambled,omitempty"`
	CAIDs              []int                  `json:"caids,omitempty"`
	OnDemand           bool                   `json:"on_demand,omitempty"`
	OnDemandTimeoutSec int                    `json:"on_demand_timeout_sec,omitempty"`
	XMLTVChannelID     string                 `json:"xmltv_channel_id,omitempty"`
}

type PacketSource interface {
	ReadPacket() ([]byte, error)
	Close() error
}

type StreamRuntime struct {
	State         string                  `json:"state"`
	Since         time.Time               `json:"since"`
	UptimeSeconds int64                   `json:"uptime_seconds"`
	RestartCount  int                     `json:"restart_count"`
	LastError     string                  `json:"last_error,omitempty"`
	Packets       uint64                  `json:"packets"`
	BitrateKbps   int                     `json:"bitrate_kbps"`
	Signal        *DVBSignal              `json:"signal,omitempty"`
	Placement     *DVBPlacementRuntime    `json:"placement,omitempty"`
	Descrambling  *DVBDescramblingRuntime `json:"descrambling,omitempty"`
}

type DVBSignal struct {
	Locked            bool   `json:"locked"`
	SignalPercent     int    `json:"signal_percent"`
	SNRPercent        int    `json:"snr_percent"`
	BER               uint32 `json:"ber"`
	UncorrectedBlocks uint32 `json:"uncorrected_blocks"`
	StatusBits        uint32 `json:"status_bits"`
}

type Settings struct {
	ExternalAPI             ExternalAPISettings `json:"external_api,omitzero"`
	HTTPPlayPort            int                 `json:"http_play_port"`
	HTTPPlayLoopback        bool                `json:"http_play_loopback,omitempty"`
	SRTPlayPort             int                 `json:"srt_play_port"`
	HTTPAllowAll            bool                `json:"http_allow_all"`
	DisableTLS              bool                `json:"disable_tls"`
	PlaylistName            string              `json:"playlist_name"`
	LogLevel                string              `json:"log_level"`
	ControlListen           string              `json:"control_listen"`
	ControlListenHTTPS      string              `json:"control_listen_https,omitempty"`
	RedirectHTTPS           bool                `json:"redirect_https,omitempty"`
	TLSMinVersion           string              `json:"tls_min_version,omitempty"`
	EPGEnabled              bool                `json:"epg_enabled,omitempty"`
	EPGSourceURLs           []string            `json:"epg_source_urls,omitempty"`
	EPGFromDVB              bool                `json:"epg_from_dvb,omitempty"`
	EPGDVBIntervalSec       int                 `json:"epg_dvb_interval_sec,omitempty"`
	EPGDVBDepth             string              `json:"epg_dvb_depth,omitempty"`
	EPGDVBPriority          bool                `json:"epg_dvb_priority,omitempty"`
	EPGLocalPath            string              `json:"epg_local_path,omitempty"`
	EPGMaxSourceMiB         int                 `json:"epg_max_source_mib,omitempty"`
	EPGSourceTimeoutSec     int                 `json:"epg_source_timeout_sec,omitempty"`
	EPGMaxProgrammes        int                 `json:"epg_max_programmes,omitempty"`
	EPGSourceRetentionHours int                 `json:"epg_source_retention_hours,omitempty"`
}

type Softcam struct {
	ID                string         `json:"id"`
	Name              string         `json:"name"`
	Type              string         `json:"type"`
	Host              string         `json:"host"`
	Port              int            `json:"port"`
	Username          string         `json:"username"`
	Password          string         `json:"password,omitempty"`
	DESKey            string         `json:"des_key,omitempty"`
	ConnectTimeoutSec int            `json:"connect_timeout_sec"`
	Enabled           bool           `json:"enabled"`
	UpdatedAt         time.Time      `json:"updated_at"`
	Runtime           SoftcamRuntime `json:"runtime"`
}

type SoftcamRuntime struct {
	Authenticated         *bool  `json:"authenticated,omitempty"`
	DescramblingSupported *bool  `json:"descrambling_supported,omitempty"`
	CardsObserved         *int   `json:"cards_observed,omitempty"`
	ErrorCode             string `json:"error_code,omitempty"`

	State         string    `json:"state"`
	Since         time.Time `json:"since"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	RestartCount  int       `json:"restart_count"`
	Connected     bool      `json:"connected"`
	LastError     string    `json:"last_error,omitempty"`
	LatencyMS     int64     `json:"latency_ms"`
}

// Clone gives each runtime/event/snapshot owner independent metadata scalars.
func (rt SoftcamRuntime) Clone() SoftcamRuntime {
	if rt.Authenticated != nil {
		v := *rt.Authenticated
		rt.Authenticated = &v
	}
	if rt.DescramblingSupported != nil {
		v := *rt.DescramblingSupported
		rt.DescramblingSupported = &v
	}
	if rt.CardsObserved != nil {
		v := *rt.CardsObserved
		rt.CardsObserved = &v
	}
	return rt
}

type SoftcamTestResult struct {
	Authenticated         *bool  `json:"authenticated,omitempty"`
	DescramblingSupported *bool  `json:"descrambling_supported,omitempty"`
	CardsObserved         *int   `json:"cards_observed,omitempty"`
	ErrorCode             string `json:"error_code,omitempty"`

	Success   bool     `json:"success"`
	Connected bool     `json:"connected"`
	LatencyMS int64    `json:"latency_ms"`
	CAIDs     []string `json:"caids,omitempty"`
	Protocol  string   `json:"protocol"`
	Error     string   `json:"error,omitempty"`
}

type AdapterProfile struct {
	ID           string                `json:"id"`
	Name         string                `json:"name"`
	Enable       bool                  `json:"enable"`
	InternalID   string                `json:"internal_id"`
	Virtual      string                `json:"virtual"`
	SATIP        bool                  `json:"sat_ip"`
	Adapter      string                `json:"adapter"`
	Type         string                `json:"type"`
	Frequency    uint32                `json:"frequency"`
	Polarization string                `json:"polarization"`
	SymbolRate   uint32                `json:"symbol_rate"`
	LNB          AdapterLNBConfig      `json:"lnb"`
	Advanced     AdapterAdvancedConfig `json:"advanced"`
	UpdatedAt    time.Time             `json:"updated_at"`
	Runtime      AdapterProfileRuntime `json:"runtime"`
}

type Service struct {
	SID            int      `json:"sid"`
	Name           string   `json:"name"`
	VideoPID       int      `json:"video_pid"`
	AudioPID       int      `json:"audio_pid"`
	PCR_PID        int      `json:"pcr_pid"`
	Type           string   `json:"type"`
	Provider       string   `json:"provider,omitempty"`
	Scrambled      bool     `json:"scrambled,omitempty"`
	HasEPG         bool     `json:"has_epg,omitempty"`
	AudioLanguages []string `json:"audio_languages,omitempty"`
	Selected       bool     `json:"selected,omitempty"`
	CAIDs          []int    `json:"caids,omitempty"`
}

type AdapterProfileRuntime struct {
	State         string     `json:"state"`
	Since         time.Time  `json:"since"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	RestartCount  int        `json:"restart_count"`
	LastError     string     `json:"last_error,omitempty"`
	Signal        *DVBSignal `json:"signal,omitempty"`
	Services      []Service  `json:"services"`
}

type AdapterLNBConfig struct {
	LOF1          int    `json:"lof1"`
	LOF2          int    `json:"lof2"`
	SLOF          int    `json:"slof"`
	ForceTone     bool   `json:"force_tone"`
	Mode          string `json:"mode"`
	UnicableSlot  int    `json:"unicable_slot"`
	SlotPosition  string `json:"slot_position"`
	SlotFrequency int    `json:"slot_frequency"`
}

type AdapterAdvancedConfig struct {
	EnableMonitoring bool   `json:"enable_monitoring"`
	Modulation       string `json:"modulation"`
	FEC              string `json:"fec"`
	RollOff          string `json:"rolloff"`
	StreamID         string `json:"stream_id"`
	TimeoutSec       int    `json:"timeout_sec"`
	DVBAPI           string `json:"dvb_api"`
	DVBAPIV3         bool   `json:"dvb_api_v3"`
}

type Adapter struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Address      string `json:"address,omitempty"`
	FrontendType string `json:"frontend_type,omitempty"`
	Model        string `json:"model,omitempty"`
	Description  string `json:"description"`
	Status       string `json:"status"`
	InUse        bool   `json:"in_use"`
	UsageCount   int    `json:"usage_count,omitempty"`
}

type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
}

type Config struct {
	APITokens            []APITokenRecord `json:"api_tokens,omitempty"`
	AdminAuthInitialized bool             `json:"admin_auth_initialized,omitempty"`
	SchemaVersion        int              `json:"schema_version,omitempty"`
	Version              string           `json:"version"`
	CreatedAt            time.Time        `json:"created_at"`
	UpdatedAt            time.Time        `json:"updated_at"`
	Streams              []Stream         `json:"streams"`
	DVBGroups            []DVBGroup       `json:"dvb_groups,omitempty"`
	DVBCards             []DVBCardConfig  `json:"dvb_cards,omitempty"`
	Softcams             []Softcam        `json:"softcams,omitempty"`
	AdapterProfiles      []AdapterProfile `json:"adapter_profiles,omitempty"`
	Settings             Settings         `json:"settings"`
}

type Status struct {
	Version         string    `json:"version"`
	StartedAt       time.Time `json:"started_at"`
	Now             time.Time `json:"now"`
	UptimeSeconds   int64     `json:"uptime_seconds"`
	TotalStreams    int       `json:"total_streams"`
	EnabledStreams  int       `json:"enabled_streams"`
	RunningStreams  int       `json:"running_streams"`
	TotalSoftcams   int       `json:"total_softcams"`
	EnabledSoftcams int       `json:"enabled_softcams"`
	OnlineSoftcams  int       `json:"online_softcams"`
	ControlEndpoint string    `json:"control_endpoint"`
}

type StateSnapshot struct {
	At              time.Time        `json:"at"`
	Status          Status           `json:"status"`
	Streams         []Stream         `json:"streams"`
	Softcams        []Softcam        `json:"softcams,omitempty"`
	AdapterProfiles []AdapterProfile `json:"adapter_profiles,omitempty"`
	Logs            []LogEntry       `json:"logs"`
}

func DefaultSettings() Settings {
	return Settings{
		ExternalAPI:             DefaultExternalAPISettings(),
		HTTPPlayPort:            8000,
		SRTPlayPort:             9000,
		HTTPAllowAll:            false,
		DisableTLS:              false,
		PlaylistName:            "playlist",
		LogLevel:                "info",
		ControlListen:           "127.0.0.1:8080",
		ControlListenHTTPS:      "0.0.0.0:8443",
		RedirectHTTPS:           false,
		TLSMinVersion:           "1.2",
		EPGFromDVB:              false,
		EPGDVBIntervalSec:       900,
		EPGDVBDepth:             "present_following",
		EPGDVBPriority:          false,
		EPGSourceRetentionHours: 24,
		EPGMaxSourceMiB:         64,
		EPGSourceTimeoutSec:     30,
		EPGMaxProgrammes:        500000,
	}
}

func DefaultAdapterLNB() AdapterLNBConfig {
	return AdapterLNBConfig{
		LOF1:          9750,
		LOF2:          10600,
		SLOF:          11700,
		ForceTone:     false,
		Mode:          "universal",
		UnicableSlot:  0,
		SlotPosition:  "A",
		SlotFrequency: 1210,
	}
}

func DefaultAdapterAdvanced() AdapterAdvancedConfig {
	return AdapterAdvancedConfig{
		EnableMonitoring: false,
		Modulation:       "auto",
		FEC:              "auto",
		RollOff:          "35",
		StreamID:         "",
		TimeoutSec:       120,
		DVBAPI:           "v5",
		DVBAPIV3:         false,
	}
}
