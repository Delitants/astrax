// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"astrax/internal/model"
	"golang.org/x/text/cases"
)

type migrationResult struct {
	migrated bool
	source   []byte
}

type migrationFileOps struct {
	backup   func(path string, now time.Time) (string, error)
	write    func(path string, cfg model.Config, expectedSource []byte) error
	readFile func(path string) ([]byte, error)
}

var (
	legacyAdapterNumber     = regexp.MustCompile(`^([0-9]+)$`)
	legacyAdapterAddress    = regexp.MustCompile(`^([0-9]+)\.([0-9]+)$`)
	legacyAdapterDevicePath = regexp.MustCompile(`^/dev/dvb/adapter([0-9]+)/frontend([0-9]+)$`)
)

func loadConfig(path string, now time.Time) (model.Config, migrationResult, error) {
	data, err := readConfigBytes(path)
	if err != nil {
		return model.Config{}, migrationResult{}, fmt.Errorf("read config: %w", err)
	}

	if err := validatePersistedEPGFetchLimits(data); err != nil {
		return model.Config{}, migrationResult{}, err
	}

	// Seed only the new field: absent legacy API settings stay disabled, while
	// explicitly invalid addresses/ports are validated rather than silently reset.
	cfg := model.Config{Settings: model.Settings{ExternalAPI: model.DefaultExternalAPISettings()}}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return model.Config{}, migrationResult{}, fmt.Errorf("parse config: %w", err)
	}
	// Absence is a legacy default; explicit zero/null must not silently acquire
	// a different retention policy during load-time normalization.
	var present struct {
		Settings struct {
			Retention json.RawMessage `json:"epg_source_retention_hours"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(data, &present); err != nil {
		return model.Config{}, migrationResult{}, fmt.Errorf("parse settings: %w", err)
	}
	if len(present.Settings.Retention) != 0 && (string(present.Settings.Retention) == "null" || cfg.Settings.EPGSourceRetentionHours < 1 || cfg.Settings.EPGSourceRetentionHours > 168) {
		return model.Config{}, migrationResult{}, fmt.Errorf("epg_source_retention_hours must be between 1 and 168")
	}
	if cfg.SchemaVersion > model.CurrentSchemaVersion {
		return model.Config{}, migrationResult{}, fmt.Errorf(
			"unsupported schema_version %d (current %d)",
			cfg.SchemaVersion,
			model.CurrentSchemaVersion,
		)
	}
	now = now.UTC()
	apiSettings, err := cfg.Settings.ExternalAPI.Normalized()
	if err != nil {
		return model.Config{}, migrationResult{}, err
	}
	cfg.Settings.ExternalAPI = apiSettings
	normalizeLoadedConfig(&cfg, now)

	migrated, changed, err := migrateConfig(cfg)
	if err != nil {
		return model.Config{}, migrationResult{}, fmt.Errorf("migrate config: %w", err)
	}
	if changed {
		migrated.UpdatedAt = now
		for i := range migrated.DVBCards {
			if migrated.DVBCards[i].UpdatedAt.IsZero() {
				migrated.DVBCards[i].UpdatedAt = now
			}
		}
	}
	return migrated, migrationResult{
		migrated: changed,
		source:   append([]byte(nil), data...),
	}, nil
}

func persistMigratedConfig(path string, cfg model.Config, result migrationResult, now time.Time, ops migrationFileOps) error {
	if !result.migrated {
		return nil
	}
	backupPath, err := ops.backup(path, now)
	if err != nil {
		return fmt.Errorf("backup legacy config: %w", err)
	}
	backupBytes, err := ops.readFile(backupPath)
	if err != nil {
		return fmt.Errorf("read verified config backup: %w", err)
	}
	if !bytes.Equal(backupBytes, result.source) {
		return fmt.Errorf("config changed after load; backup %s does not match loaded bytes", backupPath)
	}
	currentBytes, err := ops.readFile(path)
	if err != nil {
		return fmt.Errorf("re-read config before migration write: %w", err)
	}
	if !bytes.Equal(currentBytes, result.source) {
		return fmt.Errorf("config changed after load; refusing to replace %s", path)
	}
	if err := ops.write(path, cfg, result.source); err != nil {
		return fmt.Errorf("write migrated config: %w", err)
	}
	return nil
}

func defaultMigrationFileOps() migrationFileOps {
	return migrationFileOps{
		backup:   backupConfig,
		write:    writeConfigAtomicExpected,
		readFile: readConfigBytes,
	}
}

func migrateConfig(cfg model.Config) (model.Config, bool, error) {
	if cfg.SchemaVersion > model.CurrentSchemaVersion {
		return model.Config{}, false, fmt.Errorf(
			"unsupported schema_version %d (current %d)",
			cfg.SchemaVersion,
			model.CurrentSchemaVersion,
		)
	}

	cfg.Streams = cloneStreamsForMigration(cfg.Streams)
	cfg.DVBCards = append([]model.DVBCardConfig(nil), cfg.DVBCards...)
	if cfg.SchemaVersion == model.CurrentSchemaVersion {
		if err := validateMigratedConfig(cfg); err != nil {
			return model.Config{}, false, err
		}
		return cfg, false, nil
	}

	for i := range cfg.Streams {
		stream := &cfg.Streams[i]
		if !legacyDVBStream(*stream) {
			continue
		}
		profile, ok := legacyProfileByID(cfg.AdapterProfiles, stream.AdapterProfileID)
		if !ok {
			return model.Config{}, false, fmt.Errorf("stream %s: adapter profile %s not found", stream.ID, stream.AdapterProfileID)
		}
		converted, effectiveProfile, err := migrateLegacyDVBStream(*stream, profile)
		if err != nil {
			return model.Config{}, false, fmt.Errorf("stream %s: %w", stream.ID, err)
		}
		converted.DVB.Adapter = resolveLegacyStableKey(converted.DVB.Adapter, cfg.DVBCards)
		cfg.Streams[i] = converted
		ensureLegacyCardConfig(&cfg, effectiveProfile, converted.DVB.Adapter)
	}
	cfg.SchemaVersion = model.CurrentSchemaVersion
	if err := validateMigratedConfig(cfg); err != nil {
		return model.Config{}, false, err
	}
	return cfg, true, nil
}

func cloneStreamsForMigration(streams []model.Stream) []model.Stream {
	cloned := append([]model.Stream(nil), streams...)
	for i := range cloned {
		if cloned[i].DVB == nil {
			continue
		}
		dvbConfig := *cloned[i].DVB
		dvbConfig.AudioPIDs = append([]int(nil), dvbConfig.AudioPIDs...)
		if dvbConfig.RFOverride != nil {
			rf := *dvbConfig.RFOverride
			dvbConfig.RFOverride = &rf
		}
		cloned[i].DVB = &dvbConfig
	}
	return cloned
}

func legacyDVBStream(stream model.Stream) bool {
	return stream.AdapterProfileID != "" && isLegacyDVBStream(stream)
}

func legacyProfileByID(profiles []model.AdapterProfile, id string) (model.AdapterProfile, bool) {
	for _, profile := range profiles {
		if profile.ID == id {
			return profile, true
		}
	}
	return model.AdapterProfile{}, false
}

func migrateLegacyDVBStream(stream model.Stream, profile model.AdapterProfile) (model.Stream, model.AdapterProfile, error) {
	effectiveProfile := profile
	applyAdapterProfileDefaults(&effectiveProfile)

	dvbConfig, err := parseLegacyDVBURL(stream.InputURL, profile, effectiveProfile)
	if err != nil {
		return model.Stream{}, model.AdapterProfile{}, err
	}

	stream.GroupID = ""
	stream.DVB = &dvbConfig
	return stream, effectiveProfile, nil
}

func parseLegacyDVBURL(rawURL string, profile, effectiveProfile model.AdapterProfile) (model.DVBStreamConfig, error) {
	input, err := url.Parse(rawURL)
	if err != nil {
		return model.DVBStreamConfig{}, fmt.Errorf("parse legacy DVB URL: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(input.Scheme), "dvb") {
		return model.DVBStreamConfig{}, fmt.Errorf("legacy DVB input must use dvb:// scheme")
	}
	query := input.Query()

	deliveryRaw := legacyStringQuery(query, profile.Type, "delivery", "delivery_system")
	if strings.TrimSpace(deliveryRaw) == "" {
		deliveryRaw = "dvbs2"
	}
	delivery, err := normalizeLegacyDeliverySystem(deliveryRaw)
	if err != nil {
		return model.DVBStreamConfig{}, err
	}

	frequency, found, err := legacyFrequencyQuery(query, "frequency", "freq")
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	if !found {
		fallback := profile.Frequency
		if fallback == 0 && legacySatelliteDelivery(delivery) {
			fallback = effectiveProfile.Frequency
		}
		frequency, err = normalizeLegacyFrequencyKHz(uint64(fallback))
		if err != nil {
			return model.DVBStreamConfig{}, err
		}
	}
	if frequency == 0 {
		return model.DVBStreamConfig{}, fmt.Errorf("frequency must be greater than zero for %s", delivery)
	}

	symbolRate, found, err := legacyUint32Query(query, "symbol_rate")
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	if !found {
		symbolRate = profile.SymbolRate
		if symbolRate == 0 && legacySatelliteDelivery(delivery) {
			symbolRate = effectiveProfile.SymbolRate
		}
	}
	symbolRate = normalizeLegacySymbolRate(symbolRate)
	if (legacySatelliteDelivery(delivery) || delivery == "dvbc") && symbolRate == 0 {
		return model.DVBStreamConfig{}, fmt.Errorf("symbol_rate must be greater than zero for %s", delivery)
	}

	polarizationRaw := legacyStringQuery(query, profile.Polarization, "polarization")
	if strings.TrimSpace(polarizationRaw) == "" && legacySatelliteDelivery(delivery) {
		polarizationRaw = effectiveProfile.Polarization
	}
	polarization, err := normalizeLegacyPolarization(polarizationRaw)
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	if legacySatelliteDelivery(delivery) && polarization == "" {
		return model.DVBStreamConfig{}, fmt.Errorf("polarization must be H or V for %s", delivery)
	}

	serviceID, found, err := legacyIntQuery(query, "service", "service_id", "sid")
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	if !found {
		return model.DVBStreamConfig{}, fmt.Errorf("service is required")
	}
	videoPID, _, err := legacyIntQuery(query, "video_pid")
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	pcrPID, _, err := legacyIntQuery(query, "pcr_pid")
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	audioPIDs, err := legacyAudioPIDs(query)
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	adapterPolicy, err := legacyAdapterPolicy(effectiveProfile.Adapter)
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	rfOverride, err := legacyRFOverride(query, effectiveProfile.LNB)
	if err != nil {
		return model.DVBStreamConfig{}, err
	}
	advanced, err := legacyAdvancedOverride(query, effectiveProfile.Advanced)
	if err != nil {
		return model.DVBStreamConfig{}, err
	}

	config := model.DVBStreamConfig{
		DeliverySystem: delivery,
		FrequencyKHz:   frequency,
		SymbolRate:     symbolRate,
		Polarization:   polarization,
		Modulation:     advanced.Modulation,
		FEC:            advanced.FEC,
		RollOff:        advanced.RollOff,
		StreamID:       advanced.StreamID,
		ServiceID:      serviceID,
		VideoPID:       videoPID,
		AudioPIDs:      audioPIDs,
		PCRPID:         pcrPID,
		RFOverride:     &rfOverride,
		Advanced:       advanced,
		Adapter:        adapterPolicy,
	}
	config.Normalize()
	return config, nil
}

func normalizeLegacyDeliverySystem(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "dvb-s", "dvbs", "s":
		return "dvbs", nil
	case "dvb-s2", "dvbs2", "s2":
		return "dvbs2", nil
	case "dvb-c", "dvbc", "c":
		return "dvbc", nil
	case "dvb-t", "dvbt", "t":
		return "dvbt", nil
	case "dvb-t2", "dvbt2", "t2":
		return "dvbt2", nil
	default:
		return "", fmt.Errorf("unsupported legacy delivery system %q", raw)
	}
}

func legacySatelliteDelivery(delivery string) bool {
	return delivery == "dvbs" || delivery == "dvbs2"
}

func legacyFrequencyQuery(query url.Values, names ...string) (uint32, bool, error) {
	raw, found := firstLegacyQueryValue(query, names...)
	if !found {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, true, fmt.Errorf("invalid %s %q", names[0], raw)
	}
	normalized, err := normalizeLegacyFrequencyKHz(value)
	if err != nil {
		return 0, true, fmt.Errorf("invalid %s %q: %w", names[0], raw, err)
	}
	return normalized, true, nil
}

func normalizeLegacyFrequencyKHz(value uint64) (uint32, error) {
	switch {
	case value >= 1_000_000_000:
		value /= 1000
	case value >= 1_000_000:
	default:
		value *= 1000
	}
	if value > uint64(^uint32(0)) {
		return 0, fmt.Errorf("frequency exceeds uint32 kHz range")
	}
	return uint32(value), nil
}

func normalizeLegacySymbolRate(value uint32) uint32 {
	if value > 0 && value < 1_000_000 {
		return value * 1000
	}
	return value
}

func normalizeLegacyPolarization(raw string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case "H", "HORIZONTAL":
		return "H", nil
	case "V", "VERTICAL":
		return "V", nil
	default:
		return "", fmt.Errorf("invalid polarization %q", raw)
	}
}

func legacyRFOverride(query url.Values, base model.AdapterLNBConfig) (model.AdapterLNBConfig, error) {
	if value, found, err := legacyIntQuery(query, "lnb_lof_low", "lof_low"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		base.LOF1 = value
	}
	if value, found, err := legacyIntQuery(query, "lnb_lof_high", "lof_high"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		base.LOF2 = value
	}
	if value, found, err := legacyIntQuery(query, "lnb_switch", "lof_switch"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		base.SLOF = value
	}
	if value, found, err := legacyBoolQuery(query, "force_tone"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		base.ForceTone = value
	}
	if value, found, err := legacyIntQuery(query, "unicable_type", "unicable"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		switch value {
		case 0:
			base.Mode = "universal"
		case 1:
			base.Mode = "unicable1"
		case 2:
			base.Mode = "unicable2"
		default:
			return model.AdapterLNBConfig{}, fmt.Errorf("invalid unicable_type %d", value)
		}
	}
	if value, found, err := legacyIntQuery(query, "unicable_slot", "scr"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		base.UnicableSlot = value
	}
	if value, found, err := legacyIntQuery(query, "unicable_freq", "ub_freq"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		base.SlotFrequency = value
	}
	if value, found, err := legacyIntQuery(query, "diseqc_port"); err != nil {
		return model.AdapterLNBConfig{}, err
	} else if found {
		positions := []string{"A", "B", "C", "D"}
		if value < 0 || value >= len(positions) {
			return model.AdapterLNBConfig{}, fmt.Errorf("invalid diseqc_port %d", value)
		}
		base.SlotPosition = positions[value]
	}
	return base, nil
}

func legacyAdvancedOverride(query url.Values, base model.AdapterAdvancedConfig) (model.AdapterAdvancedConfig, error) {
	base.Modulation = legacyStringQuery(query, base.Modulation, "modulation")
	base.FEC = legacyStringQuery(query, base.FEC, "fec")
	base.RollOff = legacyStringQuery(query, base.RollOff, "rolloff", "roll_off")
	base.StreamID = legacyStringQuery(query, base.StreamID, "stream_id")
	base.DVBAPI = legacyStringQuery(query, base.DVBAPI, "dvb_api")
	if value, found, err := legacyIntQuery(query, "timeout_sec"); err != nil {
		return model.AdapterAdvancedConfig{}, err
	} else if found {
		base.TimeoutSec = value
	}
	if value, found, err := legacyBoolQuery(query, "enable_monitoring"); err != nil {
		return model.AdapterAdvancedConfig{}, err
	} else if found {
		base.EnableMonitoring = value
	}
	if value, found, err := legacyBoolQuery(query, "dvb_api_v3"); err != nil {
		return model.AdapterAdvancedConfig{}, err
	} else if found {
		base.DVBAPIV3 = value
	} else if strings.EqualFold(base.DVBAPI, "v3") {
		base.DVBAPIV3 = true
	}
	return base, nil
}

func legacyBoolQuery(query url.Values, names ...string) (bool, bool, error) {
	raw, found := firstLegacyQueryValue(query, names...)
	if !found {
		return false, false, nil
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true, true, nil
	case "0", "false", "no", "off":
		return false, true, nil
	default:
		return false, true, fmt.Errorf("invalid %s %q", names[0], raw)
	}
}

func legacyAdapterPolicy(raw string) (model.DVBAdapterPolicy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.EqualFold(raw, "auto") {
		return model.DVBAdapterPolicy{Mode: "auto"}, nil
	}

	var match []string
	switch {
	case legacyAdapterNumber.MatchString(raw):
		match = legacyAdapterNumber.FindStringSubmatch(raw)
		match = append(match, "0")
	case legacyAdapterAddress.MatchString(raw):
		match = legacyAdapterAddress.FindStringSubmatch(raw)
	case legacyAdapterDevicePath.MatchString(raw):
		match = legacyAdapterDevicePath.FindStringSubmatch(raw)
	default:
		return model.DVBAdapterPolicy{}, fmt.Errorf("invalid fixed adapter address %q", raw)
	}

	adapter, err := strconv.Atoi(match[1])
	if err != nil {
		return model.DVBAdapterPolicy{}, fmt.Errorf("invalid fixed adapter address %q", raw)
	}
	frontend, err := strconv.Atoi(match[2])
	if err != nil {
		return model.DVBAdapterPolicy{}, fmt.Errorf("invalid fixed adapter address %q", raw)
	}
	return model.DVBAdapterPolicy{
		Mode:        "fixed",
		LastAddress: fmt.Sprintf("%d.%d", adapter, frontend),
	}, nil
}

func legacyIntQuery(query url.Values, names ...string) (int, bool, error) {
	raw, found := firstLegacyQueryValue(query, names...)
	if !found {
		return 0, false, nil
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, true, fmt.Errorf("invalid %s %q", names[0], raw)
	}
	return int(value), true, nil
}

func legacyUint32Query(query url.Values, names ...string) (uint32, bool, error) {
	raw, found := firstLegacyQueryValue(query, names...)
	if !found {
		return 0, false, nil
	}
	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, true, fmt.Errorf("invalid %s %q", names[0], raw)
	}
	return uint32(value), true, nil
}

func firstLegacyQueryValue(query url.Values, names ...string) (string, bool) {
	for _, name := range names {
		for _, value := range query[name] {
			value = strings.TrimSpace(value)
			if value != "" {
				return value, true
			}
		}
	}
	return "", false
}

func legacyStringQuery(query url.Values, fallback string, names ...string) string {
	if value, ok := firstLegacyQueryValue(query, names...); ok {
		return value
	}
	return fallback
}

func legacyAudioPIDs(query url.Values) ([]int, error) {
	rawValues := append([]string(nil), query["audio_pid"]...)
	rawValues = append(rawValues, query["audio_pids"]...)
	if len(rawValues) == 0 {
		return nil, nil
	}

	pids := make([]int, 0, len(rawValues))
	for _, raw := range rawValues {
		parts := strings.FieldsFunc(raw, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		})
		if len(parts) == 0 {
			return nil, fmt.Errorf("invalid audio_pid %q", raw)
		}
		for _, part := range parts {
			pid, err := strconv.ParseInt(strings.TrimSpace(part), 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid audio_pid %q", part)
			}
			pids = append(pids, int(pid))
		}
	}
	return pids, nil
}

func resolveLegacyStableKey(policy model.DVBAdapterPolicy, cards []model.DVBCardConfig) model.DVBAdapterPolicy {
	if policy.Mode != "fixed" || policy.DeviceKey != "" || policy.LastAddress == "" {
		return policy
	}
	explicitFallback := "address:" + policy.LastAddress
	explicitMatches := 0
	stableKey := ""
	stableMatches := 0
	for _, card := range cards {
		if card.LastAddress != policy.LastAddress {
			continue
		}
		switch {
		case card.DeviceKey == explicitFallback:
			explicitMatches++
		case card.DeviceKey != "" && !strings.HasPrefix(card.DeviceKey, "address:"):
			stableKey = card.DeviceKey
			stableMatches++
		}
	}
	if explicitMatches == 1 {
		policy.DeviceKey = explicitFallback
		return policy
	}
	if explicitMatches == 0 && stableMatches == 1 {
		policy.DeviceKey = stableKey
	}
	return policy
}

func ensureLegacyCardConfig(cfg *model.Config, profile model.AdapterProfile, policy model.DVBAdapterPolicy) {
	if policy.Mode != "fixed" {
		return
	}
	for _, card := range cfg.DVBCards {
		if card.DeviceKey != "" && card.DeviceKey == policy.DeviceKey {
			return
		}
		if card.DeviceKey == "" && card.LastAddress == policy.LastAddress {
			return
		}
	}
	cfg.DVBCards = append(cfg.DVBCards, model.DVBCardConfig{
		DeviceKey:   policy.DeviceKey,
		LastAddress: policy.LastAddress,
		Alias:       profile.Name,
		Enabled:     profile.Enable,
		RFDefaults:  profile.LNB,
		Advanced:    profile.Advanced,
		UpdatedAt:   profile.UpdatedAt,
	})
}

func validateMigratedConfig(cfg model.Config) error {
	if err := validateEPGFetchLimits(cfg.Settings, true); err != nil {
		return err
	}
	if cfg.Settings.EPGSourceRetentionHours != 0 && (cfg.Settings.EPGSourceRetentionHours < 1 || cfg.Settings.EPGSourceRetentionHours > 168) {
		return fmt.Errorf("epg_source_retention_hours must be between 1 and 168")
	}
	stableKeys := make(map[string]int, len(cfg.DVBCards))
	fallbackAddresses := make(map[string]int, len(cfg.DVBCards))
	for i, card := range cfg.DVBCards {
		deviceKey := card.DeviceKey
		if deviceKey != strings.TrimSpace(deviceKey) {
			return fmt.Errorf("dvb card at index %d: device_key must be trimmed", i)
		}
		if card.LastAddress != "" && !isCanonicalDVBAddress(card.LastAddress) {
			return fmt.Errorf("dvb card at index %d: last_address %q must be canonical A.F", i, card.LastAddress)
		}

		fallback := deviceKey == "" || strings.HasPrefix(deviceKey, "address:")
		if fallback {
			if card.LastAddress == "" {
				return fmt.Errorf("dvb card at index %d: fallback identity requires canonical last_address", i)
			}
			if deviceKey != "" {
				keyAddress := strings.TrimPrefix(deviceKey, "address:")
				if !isCanonicalDVBAddress(keyAddress) {
					return fmt.Errorf("dvb card at index %d: address device_key %q must contain canonical A.F", i, deviceKey)
				}
				if keyAddress != card.LastAddress {
					return fmt.Errorf("dvb card at index %d: address device_key %q must match last_address %q", i, deviceKey, card.LastAddress)
				}
			}
			if other, exists := fallbackAddresses[card.LastAddress]; exists {
				return fmt.Errorf("dvb card at index %d: duplicate fallback address %q from index %d", i, card.LastAddress, other)
			}
			fallbackAddresses[card.LastAddress] = i
			continue
		}

		if other, exists := stableKeys[deviceKey]; exists {
			return fmt.Errorf("dvb card at index %d: duplicate stable device_key %q from index %d", i, deviceKey, other)
		}
		stableKeys[deviceKey] = i
	}

	groupIDs := make(map[string]struct{}, len(cfg.DVBGroups))
	groupNames := make(map[string]string, len(cfg.DVBGroups))
	for i, group := range cfg.DVBGroups {
		if group.ID == "" {
			return fmt.Errorf("dvb group at index %d: id is required", i)
		}
		if _, exists := groupIDs[group.ID]; exists {
			return fmt.Errorf("dvb group %s: duplicate id", group.ID)
		}
		groupIDs[group.ID] = struct{}{}

		trimmedName := strings.TrimSpace(group.Name)
		if trimmedName == "" {
			return fmt.Errorf("dvb group %s: name is required", group.ID)
		}
		if group.Name != trimmedName {
			return fmt.Errorf("dvb group %s: name must be trimmed", group.ID)
		}
		foldedName := cases.Fold().String(group.Name)
		if otherID, exists := groupNames[foldedName]; exists {
			return fmt.Errorf("dvb group %s: name duplicates group %s", group.ID, otherID)
		}
		groupNames[foldedName] = group.ID
	}

	streamIDs := make(map[string]struct{}, len(cfg.Streams))
	outputs := make(map[string]string, len(cfg.Streams))
	for i := range cfg.Streams {
		stream := &cfg.Streams[i]
		if stream.ID == "" {
			return fmt.Errorf("stream at index %d: id is required", i)
		}
		if _, exists := streamIDs[stream.ID]; exists {
			return fmt.Errorf("stream %s: duplicate id", stream.ID)
		}
		streamIDs[stream.ID] = struct{}{}
		if stream.GroupID != "" {
			if _, exists := groupIDs[stream.GroupID]; !exists {
				return fmt.Errorf("stream %s: dvb group %s not found", stream.ID, stream.GroupID)
			}
		}
		if output := strings.TrimSpace(stream.OutputURL); output != "" {
			if otherID, exists := outputs[output]; exists {
				return fmt.Errorf("stream %s: output_url duplicates stream %s", stream.ID, otherID)
			}
			outputs[output] = stream.ID
		}
		if stream.DVB == nil {
			continue
		}
		stream.DVB.Normalize()
		if stream.DVB.Adapter.Mode == "auto" && stream.DVB.Adapter.LastAddress == "0.0" {
			return fmt.Errorf("stream %s: auto adapter cannot use LastAddress 0.0", stream.ID)
		}
		if err := stream.DVB.Validate(); err != nil {
			return fmt.Errorf("stream %s: %w", stream.ID, err)
		}
	}
	return nil
}

func isCanonicalDVBAddress(address string) bool {
	parts := strings.Split(address, ".")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return false
		}
	}
	return true
}

func normalizeLoadedConfig(cfg *model.Config, now time.Time) {
	normalizeEPGFetchLimits(&cfg.Settings)
	if cfg.Settings.EPGSourceRetentionHours == 0 {
		cfg.Settings.EPGSourceRetentionHours = model.DefaultSettings().EPGSourceRetentionHours
	}
	if cfg.Version == "" {
		cfg.Version = model.DefaultVersion
	}
	if cfg.CreatedAt.IsZero() {
		cfg.CreatedAt = now.UTC()
	}
	if cfg.Settings.ControlListen == "" {
		cfg.Settings.ControlListen = model.DefaultSettings().ControlListen
	}
	if cfg.Settings.PlaylistName == "" {
		cfg.Settings.PlaylistName = "playlist"
	}
	if cfg.Settings.LogLevel == "" {
		cfg.Settings.LogLevel = "info"
	}
	if cfg.Settings.HTTPPlayPort <= 0 {
		cfg.Settings.HTTPPlayPort = 8000
	}
	if cfg.Settings.SRTPlayPort <= 0 {
		cfg.Settings.SRTPlayPort = 9000
	}

	for i := range cfg.Streams {
		cfg.Streams[i].Runtime = model.StreamRuntime{}
	}
	for i := range cfg.Softcams {
		cfg.Softcams[i].Runtime = model.SoftcamRuntime{}
		cfg.Softcams[i].Type = normalizeSoftcamType(cfg.Softcams[i].Type)
		if cfg.Softcams[i].Type == "" {
			cfg.Softcams[i].Type = "newcamd"
		}
		if !softcamRequiresDES(cfg.Softcams[i].Type) {
			cfg.Softcams[i].DESKey = ""
		}
		if cfg.Softcams[i].ConnectTimeoutSec <= 0 {
			cfg.Softcams[i].ConnectTimeoutSec = 6
		}
	}
	if cfg.Softcams == nil {
		cfg.Softcams = make([]model.Softcam, 0)
	}
	for i := range cfg.AdapterProfiles {
		applyAdapterProfileDefaults(&cfg.AdapterProfiles[i])
		cfg.AdapterProfiles[i].Runtime = model.AdapterProfileRuntime{}
	}
	if cfg.AdapterProfiles == nil {
		cfg.AdapterProfiles = make([]model.AdapterProfile, 0)
	}
}
