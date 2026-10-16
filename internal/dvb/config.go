// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"astrax/internal/model"
)

// ErrUnsupportedDeliverySystem reports a structured delivery system that the
// current Linux DVB tuner boundary cannot open.
type ErrUnsupportedDeliverySystem struct {
	Delivery string
}

func (e *ErrUnsupportedDeliverySystem) Error() string {
	return fmt.Sprintf("delivery %q is not supported by the Linux DVB backend", e.Delivery)
}

type Config struct {
	Adapter      int
	Frontend     int
	Delivery     string
	FrequencyKHz uint32
	SymbolRate   uint32
	Polarization string
	DiseqcPort   int
	UnicableType int
	UnicableSlot int
	UnicableFreq int
	UnicablePIN  int
	// UnicablePosition keeps the normalized satellite position explicit even
	// though the current Linux session also consumes it through DiseqcPort.
	UnicablePosition int
	LnbLowMHz        int
	LnbHighMHz       int
	LnbSwitchMHz     int
	ForceTone        bool
	DVBAPI           string
	DVBAPIV3         bool
	Modulation       string
	FEC              string
	RollOff          string
	StreamID         string
	VideoPID         int
	AudioPID         int
	PCR_PID          int
	ServiceID        int
}

// ConfigFromStream resolves structured stream and card settings into the
// current Linux DVB-S/S2 tuning boundary without mutating either input.
func ConfigFromStream(stream model.DVBStreamConfig, card model.DVBCardConfig, address string) (Config, error) {
	stream = cloneStructuredStream(stream)
	stream.Normalize()

	adapter, frontend, err := parseExactAdapterFrontend(address)
	if err != nil {
		return Config{}, err
	}

	delivery := normalizeDeliverySystem(stream.DeliverySystem)
	switch delivery {
	case "dvbs", "dvbs2":
	default:
		return Config{}, &ErrUnsupportedDeliverySystem{Delivery: delivery}
	}
	stream.DeliverySystem = delivery
	if err := stream.Validate(); err != nil {
		return Config{}, err
	}

	rf := card.RFDefaults
	if stream.RFOverride != nil {
		rf = *stream.RFOverride
	}
	rf, unicableType, position, err := normalizeSatelliteRF(rf)
	if err != nil {
		return Config{}, err
	}

	advanced, err := resolveAdvanced(stream, card.Advanced, delivery)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		Adapter:          adapter,
		Frontend:         frontend,
		Delivery:         delivery,
		FrequencyKHz:     stream.FrequencyKHz,
		SymbolRate:       stream.SymbolRate,
		Polarization:     normalizePolarization(stream.Polarization),
		DiseqcPort:       position,
		UnicableType:     unicableType,
		UnicableSlot:     rf.UnicableSlot,
		UnicableFreq:     rf.SlotFrequency,
		UnicablePIN:      -1,
		UnicablePosition: position,
		LnbLowMHz:        rf.LOF1,
		LnbHighMHz:       rf.LOF2,
		LnbSwitchMHz:     rf.SLOF,
		ForceTone:        rf.ForceTone,
		DVBAPI:           advanced.DVBAPI,
		DVBAPIV3:         advanced.DVBAPIV3,
		Modulation:       advanced.Modulation,
		FEC:              advanced.FEC,
		RollOff:          advanced.RollOff,
		StreamID:         advanced.StreamID,
		VideoPID:         stream.VideoPID,
		PCR_PID:          stream.PCRPID,
		ServiceID:        stream.ServiceID,
	}
	if len(stream.AudioPIDs) > 0 {
		cfg.AudioPID = stream.AudioPIDs[0]
	}
	if unicableType == 0 {
		cfg.UnicableSlot = 0
		cfg.UnicableFreq = 0
	}
	return cfg, nil
}

// ValidateStreamForLinux validates stream-owned tune fields without depending
// on a card inventory. Card-specific defaults are validated when a card is
// resolved by ConfigFromStream.
func ValidateStreamForLinux(stream model.DVBStreamConfig) error {
	_, err := ConfigFromStream(stream, model.DVBCardConfig{
		RFDefaults: model.DefaultAdapterLNB(),
		Advanced:   model.DefaultAdapterAdvanced(),
	}, "0.0")
	return err
}

func cloneStructuredStream(in model.DVBStreamConfig) model.DVBStreamConfig {
	out := in
	out.AudioPIDs = append([]int(nil), in.AudioPIDs...)
	if in.RFOverride != nil {
		rf := *in.RFOverride
		out.RFOverride = &rf
	}
	return out
}

func parseExactAdapterFrontend(address string) (int, int, error) {
	adapterText, frontendText, found := strings.Cut(address, ".")
	if !found || adapterText == "" || frontendText == "" || strings.Contains(frontendText, ".") || !decimalDigits(adapterText) || !decimalDigits(frontendText) {
		return 0, 0, fmt.Errorf("DVB address %q must be exact non-negative adapter.frontend", address)
	}
	adapter, err := strconv.ParseUint(adapterText, 10, strconv.IntSize)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid DVB adapter in address %q: %w", address, err)
	}
	frontend, err := strconv.ParseUint(frontendText, 10, strconv.IntSize)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid DVB frontend in address %q: %w", address, err)
	}
	if strconv.FormatUint(adapter, 10) != adapterText || strconv.FormatUint(frontend, 10) != frontendText {
		return 0, 0, fmt.Errorf("DVB address %q must use canonical adapter.frontend decimals", address)
	}
	return int(adapter), int(frontend), nil
}

func decimalDigits(value string) bool {
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return value != ""
}

func normalizeDeliverySystem(value string) string {
	value, _ = model.CanonicalDVBDeliverySystem(value)
	return value
}

func normalizePolarization(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "H", "HORIZONTAL":
		return "H"
	case "V", "VERTICAL":
		return "V"
	default:
		return strings.ToUpper(strings.TrimSpace(value))
	}
}

func normalizeSatelliteRF(in model.AdapterLNBConfig) (model.AdapterLNBConfig, int, int, error) {
	out := in
	rawMode := strings.ToLower(strings.TrimSpace(out.Mode))
	mode := compactToken(rawMode)
	if mode == "" {
		mode = "universal"
	}
	switch {
	case mode == "universal":
		out.Mode = "universal"
	case hasDelimitedToken(rawMode, "custom"):
		out.Mode = "custom"
	case mode == "unicable" || mode == "unicable1" || mode == "unicablei" || mode == "en50494":
		out.Mode = "unicable1"
	case mode == "unicable2" || mode == "unicableii" || mode == "jess" || mode == "en50607":
		out.Mode = "unicable2"
	default:
		return model.AdapterLNBConfig{}, 0, 0, fmt.Errorf("unsupported satellite RF mode %q", in.Mode)
	}
	out.SlotPosition = strings.ToUpper(strings.TrimSpace(out.SlotPosition))
	if out.SlotPosition == "" {
		out.SlotPosition = "A"
	}
	if out.LOF1 <= 0 || out.LOF2 <= 0 || out.SLOF <= 0 {
		return model.AdapterLNBConfig{}, 0, 0, fmt.Errorf("satellite LNB requires positive LOF1, LOF2, and SLOF")
	}

	unicableType := 0
	maxPosition := 3
	switch out.Mode {
	case "unicable1":
		unicableType = 1
		maxPosition = 1
		if out.UnicableSlot < 1 || out.UnicableSlot > 8 {
			return model.AdapterLNBConfig{}, 0, 0, fmt.Errorf("Unicable I slot must be between 1 and 8")
		}
	case "unicable2":
		unicableType = 2
		if out.UnicableSlot < 1 || out.UnicableSlot > 32 {
			return model.AdapterLNBConfig{}, 0, 0, fmt.Errorf("Unicable II slot must be between 1 and 32")
		}
	}
	if unicableType > 0 && out.SlotFrequency <= 0 {
		return model.AdapterLNBConfig{}, 0, 0, fmt.Errorf("Unicable user-band frequency must be positive")
	}
	position := strings.Index("ABCD", out.SlotPosition)
	if len(out.SlotPosition) != 1 || position < 0 || position > maxPosition {
		allowed := "A-D"
		if maxPosition == 1 {
			allowed = "A-B"
		}
		return model.AdapterLNBConfig{}, 0, 0, fmt.Errorf("satellite position for %s must be %s", out.Mode, allowed)
	}
	return out, unicableType, position, nil
}

func hasDelimitedToken(value, target string) bool {
	for _, token := range strings.FieldsFunc(value, func(char rune) bool {
		return char == '-' || char == '_' || unicode.IsSpace(char)
	}) {
		if token == target {
			return true
		}
	}
	return false
}

func resolveAdvanced(stream model.DVBStreamConfig, card model.AdapterAdvancedConfig, delivery string) (model.AdapterAdvancedConfig, error) {
	out := card
	override := stream.Advanced
	if override.Modulation != "" {
		out.Modulation = override.Modulation
	}
	if override.FEC != "" {
		out.FEC = override.FEC
	}
	if override.RollOff != "" {
		out.RollOff = override.RollOff
	}
	if override.StreamID != "" {
		out.StreamID = override.StreamID
	}
	if override.TimeoutSec != 0 {
		out.TimeoutSec = override.TimeoutSec
	}
	if override.DVBAPI != "" {
		out.DVBAPI = override.DVBAPI
		out.DVBAPIV3 = override.DVBAPIV3
	} else if override.DVBAPIV3 {
		out.DVBAPI = "v3"
		out.DVBAPIV3 = true
	}
	if override.EnableMonitoring {
		out.EnableMonitoring = true
	}

	if stream.Modulation != "" {
		out.Modulation = stream.Modulation
	}
	if stream.FEC != "" {
		out.FEC = stream.FEC
	}
	if stream.RollOff != "" {
		out.RollOff = stream.RollOff
	}
	if stream.StreamID != "" {
		out.StreamID = stream.StreamID
	}

	defaults := model.DefaultAdapterAdvanced()
	if strings.TrimSpace(out.Modulation) == "" {
		out.Modulation = defaults.Modulation
	}
	if strings.TrimSpace(out.FEC) == "" {
		out.FEC = defaults.FEC
	}
	if strings.TrimSpace(out.RollOff) == "" {
		out.RollOff = defaults.RollOff
	}
	if out.TimeoutSec == 0 {
		out.TimeoutSec = defaults.TimeoutSec
	}
	if out.TimeoutSec < 0 {
		return model.AdapterAdvancedConfig{}, fmt.Errorf("advanced timeout_sec must be non-negative")
	}

	var err error
	out.Modulation, err = normalizeModulation(out.Modulation, delivery)
	if err != nil {
		return model.AdapterAdvancedConfig{}, err
	}
	out.FEC, err = normalizeFEC(out.FEC)
	if err != nil {
		return model.AdapterAdvancedConfig{}, err
	}
	out.RollOff, err = normalizeRollOff(out.RollOff)
	if err != nil {
		return model.AdapterAdvancedConfig{}, err
	}
	out.StreamID, err = normalizeStreamID(out.StreamID, delivery)
	if err != nil {
		return model.AdapterAdvancedConfig{}, err
	}
	out.DVBAPI = strings.ToLower(strings.TrimSpace(out.DVBAPI))
	if out.DVBAPI == "" {
		if out.DVBAPIV3 {
			out.DVBAPI = "v3"
		} else {
			out.DVBAPI = defaults.DVBAPI
		}
	}
	switch out.DVBAPI {
	case "v3":
		out.DVBAPIV3 = true
	case "v5":
		out.DVBAPIV3 = false
	default:
		return model.AdapterAdvancedConfig{}, fmt.Errorf("unsupported dvb_api %q", out.DVBAPI)
	}
	return out, nil
}

func normalizeModulation(value, delivery string) (string, error) {
	raw := value
	value = compactToken(value)
	var normalized string
	switch value {
	case "auto":
		normalized = "auto"
	case "psk", "qpsk":
		normalized = "qpsk"
	case "8psk", "psk8":
		normalized = "8psk"
	case "16apsk", "apsk16":
		normalized = "16apsk"
	case "32apsk", "apsk32":
		normalized = "32apsk"
	default:
		return "", fmt.Errorf("unsupported modulation %q", strings.TrimSpace(raw))
	}
	if delivery == "dvbs" && normalized != "auto" && normalized != "qpsk" {
		return "", fmt.Errorf("modulation %q is not supported for DVB-S", strings.TrimSpace(raw))
	}
	return normalized, nil
}

func normalizeFEC(value string) (string, error) {
	raw := value
	value = strings.ToLower(removeSpace(value))
	var normalized string
	switch value {
	case "auto":
		normalized = "auto"
	case "12", "1/2":
		normalized = "1/2"
	case "23", "2/3":
		normalized = "2/3"
	case "34", "3/4":
		normalized = "3/4"
	case "45", "4/5":
		normalized = "4/5"
	case "56", "5/6":
		normalized = "5/6"
	case "67", "6/7":
		normalized = "6/7"
	case "78", "7/8":
		normalized = "7/8"
	case "89", "8/9":
		normalized = "8/9"
	case "35", "3/5":
		normalized = "3/5"
	case "910", "9/10":
		normalized = "9/10"
	default:
		return "", fmt.Errorf("unsupported FEC %q", strings.TrimSpace(raw))
	}
	return normalized, nil
}

func normalizeRollOff(value string) (string, error) {
	raw := value
	value = strings.ToLower(removeSpace(value))
	var normalized string
	switch value {
	case "auto":
		normalized = "auto"
	case "20":
		normalized = "20"
	case "0.20":
		normalized = "20"
	case "25":
		normalized = "25"
	case "0.25":
		normalized = "25"
	case "35":
		normalized = "35"
	case "0.35":
		normalized = "35"
	default:
		return "", fmt.Errorf("unsupported roll-off %q", strings.TrimSpace(raw))
	}
	return normalized, nil
}

func normalizeStreamID(value, delivery string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if delivery != "dvbs2" {
		return "", fmt.Errorf("stream_id is only supported for DVB-S2")
	}
	if !decimalDigits(value) {
		return "", fmt.Errorf("stream_id %q must be a decimal DVB-S2 ISI", value)
	}
	numeric, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return "", fmt.Errorf("stream_id %q must be between 0 and 255", value)
	}
	return strconv.FormatUint(numeric, 10), nil
}

func compactToken(value string) string {
	value = strings.ToLower(removeSpace(value))
	return strings.NewReplacer("-", "", "_", "").Replace(value)
}

func removeSpace(value string) string {
	return strings.Map(func(char rune) rune {
		if unicode.IsSpace(char) {
			return -1
		}
		return char
	}, strings.TrimSpace(value))
}

type Signal struct {
	Locked            bool
	SignalPercent     int
	SNRPercent        int
	BER               uint32
	UncorrectedBlocks uint32
	StatusBits        uint32
}

type Service struct {
	SID            int
	Name           string
	VideoPID       int
	AudioPID       int
	PCR_PID        int
	Type           string
	Provider       string
	Scrambled      bool
	HasEPG         bool
	AudioLanguages []string
	CAIDs          []int
}

type Session interface {
	Poll() (Signal, error)
	ScanServices() ([]Service, error)
	OpenDemux(videoPID, audioPID, pcrPID int) (DemuxReader, error)
	Close() error
	DemuxPath() string
}

type DemuxReader interface {
	ReadPacket() ([]byte, error)
	Close() error
}

func ParseConfig(rawURL string) (Config, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Config{}, fmt.Errorf("parse dvb url: %w", err)
	}
	if strings.ToLower(u.Scheme) != "dvb" {
		return Config{}, fmt.Errorf("dvb input must use dvb:// scheme")
	}

	q := u.Query()
	cfg := Config{
		Adapter:      intOrDefault(q.Get("adapter"), 0),
		Frontend:     intOrDefault(q.Get("frontend"), 0),
		Delivery:     strings.ToLower(defaultIfEmpty(q.Get("delivery"), "dvbs2")),
		SymbolRate:   uint32(intOrDefault(q.Get("symbol_rate"), 27500000)),
		Polarization: strings.ToUpper(defaultIfEmpty(q.Get("polarization"), "H")),
		DiseqcPort:   intOrDefault(q.Get("diseqc_port"), 0),
		UnicableType: intOrDefault(defaultIfEmpty(q.Get("unicable_type"), q.Get("unicable")), 0),
		UnicableSlot: intOrDefault(defaultIfEmpty(q.Get("unicable_slot"), q.Get("scr")), 0),
		UnicableFreq: intOrDefault(defaultIfEmpty(q.Get("unicable_freq"), q.Get("ub_freq")), 1210),
		UnicablePIN:  intOrDefault(defaultIfEmpty(q.Get("unicable_pin"), q.Get("pin")), -1),
		LnbLowMHz:    intOrDefault(defaultIfEmpty(q.Get("lnb_lof_low"), q.Get("lof_low")), 9750),
		LnbHighMHz:   intOrDefault(defaultIfEmpty(q.Get("lnb_lof_high"), q.Get("lof_high")), 10600),
		LnbSwitchMHz: intOrDefault(defaultIfEmpty(q.Get("lnb_switch"), q.Get("lof_switch")), 11700),
		ForceTone:    boolOrDefault(q.Get("force_tone"), false),
		VideoPID:     intOrDefault(q.Get("video_pid"), 0),
		AudioPID:     intOrDefault(q.Get("audio_pid"), 0),
		PCR_PID:      intOrDefault(q.Get("pcr_pid"), 0),
		ServiceID:    intOrDefault(q.Get("service"), 0),
	}
	switch cfg.Delivery {
	case "dvb-s":
		cfg.Delivery = "dvbs"
	case "dvb-s2":
		cfg.Delivery = "dvbs2"
	}

	freqRaw := defaultIfEmpty(q.Get("frequency"), q.Get("freq"))
	if freqRaw == "" {
		return Config{}, fmt.Errorf("dvb frequency is required")
	}
	freq, err := parseFrequencyToKHz(freqRaw)
	if err != nil {
		return Config{}, err
	}
	cfg.FrequencyKHz = freq

	if cfg.Adapter < 0 || cfg.Frontend < 0 {
		return Config{}, fmt.Errorf("adapter/frontend must be >= 0")
	}
	if cfg.SymbolRate == 0 {
		return Config{}, fmt.Errorf("symbol_rate must be > 0")
	}
	if cfg.FrequencyKHz == 0 {
		return Config{}, fmt.Errorf("frequency must be > 0")
	}
	if cfg.DiseqcPort < 0 {
		return Config{}, fmt.Errorf("diseqc_port must be >= 0")
	}
	if cfg.UnicableType == 0 && cfg.DiseqcPort > 3 {
		return Config{}, fmt.Errorf("diseqc_port for non-unicable mode must be between 0 and 3")
	}
	if cfg.UnicableType > 0 && cfg.DiseqcPort > 15 {
		return Config{}, fmt.Errorf("diseqc_port for unicable mode must be between 0 and 15")
	}
	if cfg.UnicableType < 0 || cfg.UnicableType > 2 {
		return Config{}, fmt.Errorf("unicable_type must be 0, 1 or 2")
	}
	if cfg.UnicableType > 0 {
		maxSlot := 8
		if cfg.UnicableType == 2 {
			maxSlot = 32
		}
		if cfg.UnicableSlot < 1 || cfg.UnicableSlot > maxSlot {
			return Config{}, fmt.Errorf("unicable slot must be between 1 and %d", maxSlot)
		}
		if cfg.UnicableFreq <= 0 {
			return Config{}, fmt.Errorf("unicable frequency must be > 0")
		}
		if cfg.UnicablePIN > 0xff {
			return Config{}, fmt.Errorf("unicable pin must be between 0 and 255")
		}
	}
	if cfg.UnicableType == 0 && cfg.UnicablePIN != -1 {
		return Config{}, fmt.Errorf("unicable pin requires unicable_type 1 or 2")
	}

	if cfg.Delivery != "dvbs" && cfg.Delivery != "dvbs2" {
		return Config{}, fmt.Errorf("delivery %q is not supported yet (use dvbs or dvbs2)", cfg.Delivery)
	}

	if cfg.Polarization != "H" && cfg.Polarization != "V" {
		return Config{}, fmt.Errorf("polarization must be H or V")
	}

	return cfg, nil
}

func IntermediateFrequencyKHz(cfg Config) uint32 {
	rfMHz := float64(cfg.FrequencyKHz) / 1000.0
	lof := float64(cfg.LnbLowMHz)
	if rfMHz >= float64(cfg.LnbSwitchMHz) {
		lof = float64(cfg.LnbHighMHz)
	}
	ifMHz := rfMHz - lof
	if ifMHz < 0 {
		ifMHz = -ifMHz
	}
	return uint32(ifMHz * 1000)
}

func IsHighBand(cfg Config) bool {
	rfMHz := float64(cfg.FrequencyKHz) / 1000.0
	return rfMHz >= float64(cfg.LnbSwitchMHz)
}

func IsHorizontal(cfg Config) bool {
	return strings.ToUpper(cfg.Polarization) == "H"
}

func intOrDefault(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fallback
	}
	return v
}

func boolOrDefault(raw string, fallback bool) bool {
	if raw == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func defaultIfEmpty(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func parseFrequencyToKHz(raw string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid frequency %q", raw)
	}

	// Heuristics:
	// >= 1e9: value is in Hz
	// >= 1e6: value is in kHz
	// otherwise: value is in MHz
	switch {
	case v >= 1_000_000_000:
		return uint32(v / 1000), nil
	case v >= 1_000_000:
		return uint32(v), nil
	default:
		return uint32(v * 1000), nil
	}
}
