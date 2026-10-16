//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package adapters

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"astrax/internal/model"
)

const (
	ioctlTypeDVB = uintptr('o')

	iocNRBits   = 8
	iocTypeBits = 8
	iocSizeBits = 14
	iocDirBits  = 2

	iocNRShift   = 0
	iocTypeShift = iocNRShift + iocNRBits
	iocSizeShift = iocTypeShift + iocTypeBits
	iocDirShift  = iocSizeShift + iocSizeBits

	iocRead = 2

	maxProcPIDEntries = 4096
	maxProcFDLinks    = 16384
)

type frontendNode struct {
	adapter  int
	frontend int
	path     string
}

type frontendInspection struct {
	model           string
	frontendType    string
	deliverySystems []string
	openErr         error
}

type frontendInspector func(frontendNode, string) frontendInspection

type externalOwner struct {
	// free means a complete bounded snapshot found no owner, not exclusive access.
	// The zero value is unknown and must never permit frontend metadata access.
	free    bool
	pid     int
	command string
	warning string
}

type externalOwnersLookup func(context.Context, string, []string) (map[string]externalOwner, error)
type deviceKeyFunc func(identityMaterial string) string
type readDirFunc func(string) ([]os.DirEntry, error)

type detectionDeps struct {
	inspect      frontendInspector
	lookupOwners externalOwnersLookup
	deviceKey    deviceKeyFunc
	readDir      readDirFunc
}

type dvbFrontendInfo struct {
	Name                [128]byte
	FrontendType        uint32
	FrequencyMin        uint32
	FrequencyMax        uint32
	FrequencyStepSize   uint32
	FrequencyTolerance  uint32
	SymbolRateMin       uint32
	SymbolRateMax       uint32
	SymbolRateTolerance uint32
	NotifierDelay       uint32
	Caps                uint32
}

type identityCandidate struct {
	node             frontendNode
	physicalPath     string
	physicalRelative string
	manufacturer     string
	model            string
	metadata         []string
	deviceKey        string
	warning          string
}

var ioctlGetFrontendInfo = ior(ioctlTypeDVB, 61, unsafe.Sizeof(dvbFrontendInfo{}))

func linuxDVBCards(ctx context.Context) ([]model.DVBCard, error) {
	return detectDVBAtContext(ctx, "/dev", "/sys", "/proc", systemFrontendInspector)
}

func linuxDVBAdapters() []model.Adapter {
	cards, err := linuxDVBCards(context.Background())
	if err != nil || len(cards) == 0 {
		return []model.Adapter{{
			ID:          "dvb",
			Type:        "dvb",
			Description: "No DVB adapters detected",
			Status:      "idle",
		}}
	}

	items := make([]model.Adapter, 0, len(cards))
	for _, card := range cards {
		items = append(items, legacyAdapterFromCard(card))
	}
	return items
}

func detectDVBAt(devRoot, sysRoot, procRoot string, inspect frontendInspector) []model.DVBCard {
	cards, _ := detectDVBAtContext(context.Background(), devRoot, sysRoot, procRoot, inspect)
	return cards
}

func detectDVBAtContext(ctx context.Context, devRoot, sysRoot, procRoot string, inspect frontendInspector) ([]model.DVBCard, error) {
	return detectDVBAtWithDepsContext(ctx, devRoot, sysRoot, procRoot, defaultDetectionDeps(inspect))
}

func defaultDetectionDeps(inspect frontendInspector) detectionDeps {
	if inspect == nil {
		inspect = systemFrontendInspector
	}
	return detectionDeps{
		inspect:      inspect,
		lookupOwners: findExternalOwnersContext,
		deviceKey:    stableDeviceKey,
		readDir:      os.ReadDir,
	}
}

func detectDVBAtWithDeps(devRoot, sysRoot, procRoot string, deps detectionDeps) []model.DVBCard {
	cards, _ := detectDVBAtWithDepsContext(context.Background(), devRoot, sysRoot, procRoot, deps)
	return cards
}

func detectDVBAtWithDepsContext(ctx context.Context, devRoot, sysRoot, procRoot string, deps detectionDeps) ([]model.DVBCard, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if deps.inspect == nil {
		deps.inspect = systemFrontendInspector
	}
	if deps.lookupOwners == nil {
		deps.lookupOwners = findExternalOwnersContext
	}
	if deps.deviceKey == nil {
		deps.deviceKey = stableDeviceKey
	}
	if deps.readDir == nil {
		deps.readDir = os.ReadDir
	}

	nodes, err := collectFrontendNodesAtContext(ctx, devRoot, deps.readDir)
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []model.DVBCard{}, nil
	}

	candidates, inventory, err := buildIdentityCandidatesContext(ctx, nodes, sysRoot)
	if err != nil {
		return nil, err
	}
	if err := assignStableDeviceKeysContext(ctx, candidates, inventory, deps.deviceKey); err != nil {
		return nil, err
	}

	// Snapshot every candidate before any frontend open: even a read-only open can
	// affect shared hardware. Unknown/incomplete ownership must fail closed.
	devicePaths := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		devicePaths = append(devicePaths, candidate.node.path)
	}
	owners, err := deps.lookupOwners(ctx, procRoot, devicePaths)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, fmt.Errorf("inspect external DVB owners: %w", err)
	}

	cards := make([]model.DVBCard, 0, len(candidates))
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		owner := owners[candidate.node.path]
		owned := owner.pid != 0 || owner.command != ""
		free := owner.free && !owned && strings.TrimSpace(owner.warning) == ""
		if !owned && !free && strings.TrimSpace(owner.warning) == "" {
			owner.warning = "external owner unknown: batch lookup returned no conclusive result"
		}
		var inspection frontendInspection
		if free {
			inspection = deps.inspect(candidate.node, sysRoot)
		} else {
			// Preserve sysfs capabilities and identity without querying hardware.
			inspection.deliverySystems = readFrontendDeliverySystemsAt(sysRoot, candidate.node.adapter, candidate.node.frontend)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		modelName := strings.TrimSpace(inspection.model)
		if modelName == "" {
			modelName = candidate.model
		}
		if modelName == "" {
			modelName = "Unknown frontend"
		}
		frontendType, deliverySystems := effectiveFrontendCapabilities(modelName, inspection.frontendType, inspection.deliverySystems)

		address := fmt.Sprintf("%d.%d", candidate.node.adapter, candidate.node.frontend)
		card := model.DVBCard{
			ID:              candidate.deviceKey,
			DeviceKey:       candidate.deviceKey,
			Address:         address,
			Adapter:         candidate.node.adapter,
			Frontend:        candidate.node.frontend,
			FrontendType:    frontendType,
			DeliverySystems: deliverySystems,
			Manufacturer:    candidate.manufacturer,
			Model:           modelName,
			SysfsPath:       candidate.physicalPath,
			DevicePath:      candidate.node.path,
			Present:         true,
			Status:          "available",
			OwnerPID:        owner.pid,
			OwnerCommand:    owner.command,
			Warning:         appendWarning(candidate.warning, owner.warning),
		}

		switch {
		case owned:
			card.Status = "busy_external"
		case !free:
			card.Status = "error"
			card.LastError = owner.warning
		case inspection.openErr == nil:
		case errors.Is(inspection.openErr, syscall.EBUSY):
			card.Status = "busy_external"
			card.Warning = appendWarning(card.Warning, "external owner unknown: frontend became busy after ownership snapshot")
			card.LastError = fmt.Sprintf("read frontend metadata: %v", inspection.openErr)
		default:
			card.Status = "error"
			card.LastError = fmt.Sprintf("read frontend metadata: %v", inspection.openErr)
		}
		cards = append(cards, card)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return cards, nil
}

func collectFrontendNodesAt(devRoot string) []frontendNode {
	nodes, _ := collectFrontendNodesAtContext(context.Background(), devRoot, os.ReadDir)
	return nodes
}

func collectFrontendNodesAtContext(ctx context.Context, devRoot string, readDir readDirFunc) ([]frontendNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dvbRoot := filepath.Join(devRoot, "dvb")
	adapterEntries, err := readDir(dvbRoot)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if errors.Is(err, os.ErrNotExist) {
		return []frontendNode{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enumerate %s: %w", dvbRoot, err)
	}

	nodes := make([]frontendNode, 0, len(adapterEntries))
	for _, adapterEntry := range adapterEntries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		adapter, ok := numericSuffix(adapterEntry.Name(), "adapter")
		if !ok {
			continue
		}
		adapterPath := filepath.Join(dvbRoot, adapterEntry.Name())
		frontendEntries, err := readDir(adapterPath)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("enumerate %s: %w", adapterPath, err)
		}
		for _, frontendEntry := range frontendEntries {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			frontend, ok := numericSuffix(frontendEntry.Name(), "frontend")
			if !ok {
				continue
			}
			frontendPath := filepath.Join(adapterPath, frontendEntry.Name())
			nodes = append(nodes, frontendNode{adapter: adapter, frontend: frontend, path: frontendPath})
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].adapter != nodes[j].adapter {
			return nodes[i].adapter < nodes[j].adapter
		}
		return nodes[i].frontend < nodes[j].frontend
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

func collectSysfsFrontendNodesAt(sysRoot string) []frontendNode {
	nodes, _ := collectSysfsFrontendNodesAtContext(context.Background(), sysRoot)
	return nodes
}

func collectSysfsFrontendNodesAtContext(ctx context.Context, sysRoot string) ([]frontendNode, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(sysRoot, "class", "dvb"))
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		return nil, nil
	}

	nodes := make([]frontendNode, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		name := entry.Name()
		separator := strings.Index(name, ".frontend")
		if separator < 0 || strings.Contains(name[separator+1:], ".") {
			continue
		}
		adapter, adapterOK := numericSuffix(name[:separator], "dvb")
		frontend, frontendOK := numericSuffix(name[separator+1:], "frontend")
		if !adapterOK || !frontendOK {
			continue
		}
		nodes = append(nodes, frontendNode{adapter: adapter, frontend: frontend})
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].adapter != nodes[j].adapter {
			return nodes[i].adapter < nodes[j].adapter
		}
		return nodes[i].frontend < nodes[j].frontend
	})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nodes, nil
}

func numericSuffix(name, prefix string) (int, bool) {
	if !strings.HasPrefix(name, prefix) {
		return 0, false
	}
	raw := strings.TrimPrefix(name, prefix)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	return value, err == nil && value >= 0
}

func buildIdentityCandidates(nodes []frontendNode, sysRoot string) ([]identityCandidate, []identityCandidate) {
	candidates, inventory, _ := buildIdentityCandidatesContext(context.Background(), nodes, sysRoot)
	return candidates, inventory
}

func buildIdentityCandidatesContext(ctx context.Context, nodes []frontendNode, sysRoot string) ([]identityCandidate, []identityCandidate, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	inventoryNodes, err := collectSysfsFrontendNodesAtContext(ctx, sysRoot)
	if err != nil {
		return nil, nil, err
	}
	inventory := make([]identityCandidate, len(inventoryNodes))
	adapterDevices := make(map[int]map[string]struct{})
	for i, node := range inventoryNodes {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		candidate, err := resolveIdentityCandidateContext(ctx, node, sysRoot)
		if err != nil {
			return nil, nil, err
		}
		inventory[i] = candidate
		if candidate.physicalRelative == "" {
			continue
		}
		devices := adapterDevices[node.adapter]
		if devices == nil {
			devices = make(map[string]struct{})
			adapterDevices[node.adapter] = devices
		}
		devices[candidate.physicalRelative] = struct{}{}
	}

	for i := range inventory {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		candidate := &inventory[i]
		if len(adapterDevices[candidate.node.adapter]) != 1 {
			candidate.warning = appendWarning(candidate.warning, "ambiguous physical device identity; address may change after renumbering")
		}
	}

	candidates := make([]identityCandidate, len(nodes))
	for i, node := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		candidate, err := resolveIdentityCandidateContext(ctx, node, sysRoot)
		if err != nil {
			return nil, nil, err
		}
		candidates[i] = candidate
	}

	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		candidate := &candidates[i]
		devices := adapterDevices[candidate.node.adapter]
		_, represented := devices[candidate.physicalRelative]
		if candidate.warning == "" && (len(devices) != 1 || !represented) {
			candidate.warning = "ambiguous physical device identity; address may change after renumbering"
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	return candidates, inventory, nil
}

func resolveIdentityCandidate(node frontendNode, sysRoot string) identityCandidate {
	candidate, _ := resolveIdentityCandidateContext(context.Background(), node, sysRoot)
	return candidate
}

func resolveIdentityCandidateContext(ctx context.Context, node frontendNode, sysRoot string) (identityCandidate, error) {
	if err := ctx.Err(); err != nil {
		return identityCandidate{}, err
	}
	candidate := identityCandidate{node: node}
	canonicalRoot, err := filepath.EvalSymlinks(sysRoot)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return identityCandidate{}, ctxErr
	}
	if err != nil {
		candidate.warning = fmt.Sprintf("stable identity unavailable: resolve sysfs root: %v; address may change after renumbering", err)
		return candidate, nil
	}
	canonicalRoot, err = filepath.Abs(canonicalRoot)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return identityCandidate{}, ctxErr
	}
	if err != nil {
		candidate.warning = fmt.Sprintf("stable identity unavailable: canonicalize sysfs root: %v; address may change after renumbering", err)
		return candidate, nil
	}

	classDevicePath := filepath.Join(canonicalRoot, "class", "dvb", fmt.Sprintf("dvb%d.frontend%d", node.adapter, node.frontend), "device")
	physicalPath, err := filepath.EvalSymlinks(classDevicePath)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return identityCandidate{}, ctxErr
	}
	if err != nil {
		candidate.physicalPath = classDevicePath
		candidate.warning = fmt.Sprintf("stable identity unavailable: resolve %s: %v; address may change after renumbering", classDevicePath, err)
		return candidate, nil
	}
	physicalPath, err = filepath.Abs(physicalPath)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return identityCandidate{}, ctxErr
	}
	if err != nil {
		candidate.warning = fmt.Sprintf("stable identity unavailable: canonicalize device path: %v; address may change after renumbering", err)
		return candidate, nil
	}
	physicalPath = filepath.Clean(physicalPath)

	relative, err := filepath.Rel(canonicalRoot, physicalPath)
	if err != nil || pathEscapesRoot(relative) {
		candidate.physicalPath = physicalPath
		candidate.warning = "stable identity unavailable: sysfs device escapes configured root; address may change after renumbering"
		return candidate, nil
	}
	classRelative, err := filepath.Rel(filepath.Join(canonicalRoot, "class", "dvb"), physicalPath)
	if err == nil && !pathEscapesRoot(classRelative) {
		candidate.physicalPath = physicalPath
		candidate.warning = "ambiguous class-local physical device identity; address may change after renumbering"
		return candidate, nil
	}
	physicalRelative := filepath.ToSlash(filepath.Clean(relative))
	if physicalRelative == "devices" || !strings.HasPrefix(physicalRelative, "devices/") {
		candidate.physicalPath = physicalPath
		candidate.warning = "ambiguous non-device sysfs identity; address may change after renumbering"
		return candidate, nil
	}
	candidate.physicalRelative = physicalRelative
	info, err := os.Stat(physicalPath)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return identityCandidate{}, ctxErr
	}
	if err != nil || !info.IsDir() {
		candidate.physicalPath = physicalPath
		candidate.warning = "stable identity unavailable: physical sysfs device is not a directory; address may change after renumbering"
		return candidate, nil
	}

	candidate.physicalPath = physicalPath
	candidate.manufacturer, candidate.model, candidate.metadata, err = readStableMetadataContext(ctx, physicalPath)
	if err != nil {
		return identityCandidate{}, err
	}
	if err := ctx.Err(); err != nil {
		return identityCandidate{}, err
	}
	return candidate, nil
}

func pathEscapesRoot(relative string) bool {
	return relative == ".." || filepath.IsAbs(relative) || strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func readStableMetadata(physicalPath string) (string, string, []string) {
	manufacturer, modelName, metadata, _ := readStableMetadataContext(context.Background(), physicalPath)
	return manufacturer, modelName, metadata
}

func readStableMetadataContext(ctx context.Context, physicalPath string) (string, string, []string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", nil, err
	}
	attributes := []string{"serial", "manufacturer", "vendor", "device", "model", "subsystem_vendor", "subsystem_device"}
	metadata := make([]string, 0, len(attributes))
	manufacturer := ""
	modelName := ""
	for _, attribute := range attributes {
		if err := ctx.Err(); err != nil {
			return "", "", nil, err
		}
		payload, err := os.ReadFile(filepath.Join(physicalPath, attribute))
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", "", nil, ctxErr
		}
		if err != nil {
			continue
		}
		value := strings.Join(strings.Fields(string(payload)), " ")
		if value == "" {
			continue
		}
		if attribute == "manufacturer" {
			manufacturer = value
		}
		if attribute == "model" {
			modelName = value
		}
		metadata = append(metadata, attribute+"="+value)
	}
	if err := ctx.Err(); err != nil {
		return "", "", nil, err
	}
	return manufacturer, modelName, metadata, nil
}

func assignStableDeviceKeys(candidates, inventory []identityCandidate, keyFn deviceKeyFunc) {
	_ = assignStableDeviceKeysContext(context.Background(), candidates, inventory, keyFn)
}

func assignStableDeviceKeysContext(ctx context.Context, candidates, inventory []identityCandidate, keyFn deviceKeyFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	batchWarning, groupWarnings, err := identitySafetyWarningsContext(ctx, candidates, inventory)
	if err != nil {
		return err
	}
	if batchWarning != "" {
		for i := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			setAddressFallback(&candidates[i], batchWarning)
		}
		return ctx.Err()
	}

	adaptersByDevice := make(map[string]map[int]struct{})
	for i := range inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate := &inventory[i]
		if candidate.physicalRelative == "" {
			continue
		}
		adapters := adaptersByDevice[candidate.physicalRelative]
		if adapters == nil {
			adapters = make(map[int]struct{})
			adaptersByDevice[candidate.physicalRelative] = adapters
		}
		adapters[candidate.node.adapter] = struct{}{}
	}

	ordinals := make(map[string]map[int]int, len(adaptersByDevice))
	for physical, adapterSet := range adaptersByDevice {
		if err := ctx.Err(); err != nil {
			return err
		}
		adapterNumbers := make([]int, 0, len(adapterSet))
		for adapter := range adapterSet {
			if err := ctx.Err(); err != nil {
				return err
			}
			adapterNumbers = append(adapterNumbers, adapter)
		}
		sort.Ints(adapterNumbers)
		if err := ctx.Err(); err != nil {
			return err
		}
		ordinals[physical] = make(map[int]int, len(adapterNumbers))
		for ordinal, adapter := range adapterNumbers {
			if err := ctx.Err(); err != nil {
				return err
			}
			ordinals[physical][adapter] = ordinal
		}
	}

	keyCounts := make(map[string]int)
	for i := range inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate := &inventory[i]
		if candidate.warning != "" || groupWarnings[candidate.physicalRelative] != "" {
			continue
		}
		material, err := stableIdentityMaterialContext(ctx, *candidate, ordinals[candidate.physicalRelative][candidate.node.adapter])
		if err != nil {
			return err
		}
		deviceKey := strings.TrimSpace(keyFn(material))
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate.deviceKey = deviceKey
		if candidate.deviceKey == "" {
			setAddressFallback(candidate, "stable identity generator returned an empty key; address may change after renumbering")
			continue
		}
		keyCounts[candidate.deviceKey]++
	}

	for i := range inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate := &inventory[i]
		if candidate.warning == "" && keyCounts[candidate.deviceKey] > 1 {
			setAddressFallback(candidate, "stable device-key collision; address may change after renumbering")
		}
	}

	inventoryByAddress := make(map[string]identityCandidate, len(inventory))
	for _, candidate := range inventory {
		if err := ctx.Err(); err != nil {
			return err
		}
		inventoryByAddress[fmt.Sprintf("%d.%d", candidate.node.adapter, candidate.node.frontend)] = candidate
	}
	for i := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		candidate := &candidates[i]
		if warning := groupWarnings[candidate.physicalRelative]; warning != "" {
			setAddressFallback(candidate, warning)
			continue
		}
		if candidate.warning != "" {
			setAddressFallback(candidate, candidate.warning)
			continue
		}
		address := fmt.Sprintf("%d.%d", candidate.node.adapter, candidate.node.frontend)
		inventoryCandidate, ok := inventoryByAddress[address]
		if !ok || inventoryCandidate.physicalRelative != candidate.physicalRelative {
			setAddressFallback(candidate, "stable identity unavailable: endpoint missing from canonical sysfs inventory; address may change after renumbering")
			continue
		}
		if inventoryCandidate.warning != "" {
			setAddressFallback(candidate, inventoryCandidate.warning)
			continue
		}
		candidate.deviceKey = inventoryCandidate.deviceKey
	}
	return ctx.Err()
}

func identitySafetyWarnings(candidates, inventory []identityCandidate) (string, map[string]string) {
	batchWarning, groupWarnings, _ := identitySafetyWarningsContext(context.Background(), candidates, inventory)
	return batchWarning, groupWarnings
}

func identitySafetyWarningsContext(ctx context.Context, candidates, inventory []identityCandidate) (string, map[string]string, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	batchWarning := ""
	groupWarnings := make(map[string]string)
	inspect := func(candidate identityCandidate) {
		if candidate.physicalRelative == "" {
			warning := fmt.Sprintf("stable identity batch invalidated by unattributable sysfs endpoint %d.%d; address may change after renumbering", candidate.node.adapter, candidate.node.frontend)
			batchWarning = appendWarning(batchWarning, appendWarning(warning, candidate.warning))
			return
		}
		if candidate.warning == "" {
			return
		}
		warning := fmt.Sprintf("related sysfs endpoint %d.%d has unsafe identity; address may change after renumbering", candidate.node.adapter, candidate.node.frontend)
		groupWarnings[candidate.physicalRelative] = appendWarning(groupWarnings[candidate.physicalRelative], appendWarning(warning, candidate.warning))
	}
	for _, candidate := range inventory {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		inspect(candidate)
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}
		inspect(candidate)
	}
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	return batchWarning, groupWarnings, nil
}

func stableIdentityMaterial(candidate identityCandidate, adapterOrdinal int) string {
	material, _ := stableIdentityMaterialContext(context.Background(), candidate, adapterOrdinal)
	return material
}

func stableIdentityMaterialContext(ctx context.Context, candidate identityCandidate, adapterOrdinal int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var material strings.Builder
	material.WriteString("astrax-dvb-identity-v1\n")
	material.WriteString("physical=")
	material.WriteString(candidate.physicalRelative)
	material.WriteByte('\n')
	for _, item := range candidate.metadata {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		material.WriteString(item)
		material.WriteByte('\n')
	}
	fmt.Fprintf(&material, "adapter_ordinal=%d\nfrontend=%d\n", adapterOrdinal, candidate.node.frontend)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return material.String(), nil
}

func stableDeviceKey(identityMaterial string) string {
	sum := sha256.Sum256([]byte(identityMaterial))
	return fmt.Sprintf("dvb:%x", sum)
}

func setAddressFallback(candidate *identityCandidate, warning string) {
	address := fmt.Sprintf("%d.%d", candidate.node.adapter, candidate.node.frontend)
	candidate.deviceKey = "address:" + address
	candidate.warning = appendWarning(candidate.warning, warning)
}

func appendWarning(existing, warning string) string {
	existing = strings.TrimSpace(existing)
	warning = strings.TrimSpace(warning)
	if existing == "" {
		return warning
	}
	if warning == "" || strings.Contains(existing, warning) {
		return existing
	}
	return existing + "; " + warning
}

type frontendSyscalls struct {
	open  func(string, int, uint32) (int, error)
	ioctl func(int, uintptr, *dvbFrontendInfo) error
	close func(int) error
}

func systemFrontendSyscalls() frontendSyscalls {
	return frontendSyscalls{
		open: syscall.Open,
		ioctl: func(fd int, request uintptr, info *dvbFrontendInfo) error {
			_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(info)))
			if errno != 0 {
				return errno
			}
			return nil
		},
		close: syscall.Close,
	}
}

func systemFrontendInspector(node frontendNode, sysRoot string) frontendInspection {
	return inspectFrontendWithSyscalls(node, sysRoot, systemFrontendSyscalls())
}

func inspectFrontendWithSyscalls(node frontendNode, sysRoot string, ops frontendSyscalls) frontendInspection {
	modelName, frontendType, err := readFrontendInfo(node.path, ops)
	return frontendInspection{
		model:           modelName,
		frontendType:    frontendType,
		deliverySystems: readFrontendDeliverySystemsAt(sysRoot, node.adapter, node.frontend),
		openErr:         err,
	}
}

func effectiveFrontendCapabilities(modelName, inspectedType string, inspectedSystems []string) (string, []string) {
	deliverySystems := canonicalDeliverySystems(inspectedSystems)
	frontendType := strings.TrimSpace(inspectedType)
	inspectedCapabilities := canonicalDeliverySystems(deliverySystemsFromFrontendType(frontendType))
	if authoritativeType := summarizeDeliverySystems(deliverySystems); authoritativeType != "" && !containsAllDeliverySystems(inspectedCapabilities, deliverySystems) {
		frontendType = authoritativeType
	}
	frontendType = strings.TrimSpace(mapModelToFrontendType(modelName, frontendType))
	if frontendType == "" {
		frontendType = "unknown"
	}
	if len(deliverySystems) == 0 {
		deliverySystems = canonicalDeliverySystems(deliverySystemsFromFrontendType(frontendType))
	}
	return frontendType, deliverySystems
}

func containsAllDeliverySystems(have, want []string) bool {
	seen := make(map[string]bool, len(have))
	for _, system := range have {
		seen[system] = true
	}
	for _, system := range want {
		if !seen[system] {
			return false
		}
	}
	return true
}

func readFrontendInfo(path string, ops frontendSyscalls) (modelName string, frontendType string, err error) {
	fd, err := ops.open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", "", fmt.Errorf("open frontend read-only: %w", err)
	}
	defer func() {
		if closeErr := ops.close(fd); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close frontend: %w", closeErr))
		}
	}()

	var info dvbFrontendInfo
	if err := ops.ioctl(fd, ioctlGetFrontendInfo, &info); err != nil {
		return "", "", fmt.Errorf("FE_GET_INFO: %w", err)
	}

	name := strings.TrimSpace(strings.TrimRight(string(info.Name[:]), "\x00"))
	return name, mapFrontendType(info.FrontendType), nil
}

func readFrontendDeliverySystemsAt(sysRoot string, adapter, frontend int) []string {
	candidates := []string{
		filepath.Join(sysRoot, "class", "dvb", fmt.Sprintf("dvb%d.frontend%d", adapter, frontend), "delivery_system"),
		filepath.Join(sysRoot, "class", "dvb", fmt.Sprintf("dvb%d.frontend%d", adapter, frontend), "device", "delivery_system"),
	}
	for _, path := range candidates {
		payload, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if systems := parseDeliverySystems(string(payload)); len(systems) > 0 {
			return systems
		}
	}
	return nil
}

func parseDeliverySystems(raw string) []string {
	replacer := strings.NewReplacer("[", " ", "]", " ", ",", " ", "/", " ")
	fields := strings.Fields(replacer.Replace(raw))
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		upper := strings.ToUpper(strings.TrimSpace(field))
		upper = strings.TrimPrefix(upper, "SYS_")
		upper = strings.ReplaceAll(upper, "-", "")
		upper = strings.ReplaceAll(upper, "_", "")
		var system string
		switch upper {
		case "DVBS":
			system = "dvbs"
		case "DVBS2", "S2", "S2X":
			system = "dvbs2"
		case "DVBC", "C", "DVBCANNEXA", "DVBCANNEXB", "DVBCANNEXC":
			system = "dvbc"
		case "DVBT", "T":
			system = "dvbt"
		case "DVBT2", "T2":
			system = "dvbt2"
		case "ATSC":
			system = "atsc"
		case "ISDBT":
			system = "isdbt"
		default:
			continue
		}
		seen[system] = true
	}
	return orderedDeliverySystems(seen)
}

func canonicalDeliverySystems(raw []string) []string {
	seen := make(map[string]bool, len(raw))
	for _, item := range raw {
		for _, system := range parseDeliverySystems(item) {
			seen[system] = true
		}
	}
	return orderedDeliverySystems(seen)
}

func orderedDeliverySystems(seen map[string]bool) []string {
	order := []string{"dvbs", "dvbs2", "dvbc", "dvbt", "dvbt2", "atsc", "isdbt"}
	systems := make([]string, 0, len(seen))
	for _, system := range order {
		if seen[system] {
			systems = append(systems, system)
		}
	}
	return systems
}

func summarizeDeliverySystems(systems []string) string {
	has := make(map[string]bool, len(systems))
	for _, system := range systems {
		has[system] = true
	}
	dvb := make([]string, 0, 5)
	if has["dvbs2"] {
		dvb = append(dvb, "S", "S2")
	} else if has["dvbs"] {
		dvb = append(dvb, "S")
	}
	if has["dvbc"] {
		dvb = append(dvb, "C")
	}
	if has["dvbt2"] {
		dvb = append(dvb, "T", "T2")
	} else if has["dvbt"] {
		dvb = append(dvb, "T")
	}

	parts := make([]string, 0, 3)
	if len(dvb) > 0 {
		parts = append(parts, "DVB-"+strings.Join(dvb, "/"))
	}
	if has["atsc"] {
		parts = append(parts, "ATSC")
	}
	if has["isdbt"] {
		parts = append(parts, "ISDB-T")
	}
	return strings.Join(parts, "/")
}

func deliverySystemsFromFrontendType(frontendType string) []string {
	seen := make(map[string]bool)
	systems := make([]string, 0, 5)
	add := func(system string) {
		if !seen[system] {
			seen[system] = true
			systems = append(systems, system)
		}
	}
	for _, token := range strings.Split(strings.ToUpper(strings.TrimSpace(frontendType)), "/") {
		switch strings.TrimSpace(token) {
		case "DVB-S":
			add("dvbs")
		case "DVB-S2", "S2", "S2X":
			add("dvbs2")
		case "DVB-C":
			add("dvbc")
		case "DVB-T", "T":
			add("dvbt")
		case "DVB-T2", "T2":
			add("dvbt2")
		case "ATSC":
			add("atsc")
		case "ISDB-T":
			add("isdbt")
		}
	}
	return systems
}

func readFrontendDeliveryType(adapter, frontend int) string {
	return summarizeDeliverySystems(readFrontendDeliverySystemsAt("/sys", adapter, frontend))
}

func normalizeDeliveryLabel(raw string) string {
	clean := strings.Join(strings.Fields(raw), " ")
	clean = strings.ReplaceAll(clean, "[", "")
	clean = strings.ReplaceAll(clean, "]", "")
	upper := strings.ToUpper(clean)
	switch {
	case strings.Contains(upper, "DVBS2") || strings.Contains(upper, "DVBS"):
		return "DVB-S/S2"
	case strings.Contains(upper, "DVBT2") || strings.Contains(upper, "DVBT"):
		return "DVB-T/T2"
	case strings.Contains(upper, "DVBC"):
		return "DVB-C"
	case strings.Contains(upper, "ATSC"):
		return "ATSC"
	default:
		return strings.TrimSpace(clean)
	}
}

func mapModelToFrontendType(modelName, frontendType string) string {
	upper := strings.ToUpper(modelName)
	switch {
	case strings.Contains(upper, "6916"):
		return "DVB-S/S2/S2X"
	case strings.Contains(upper, "6590"):
		return "DVB-S/S2/S2X/T/T2/ISDB-T"
	default:
		return frontendType
	}
}

func mapFrontendType(raw uint32) string {
	switch raw {
	case 0:
		return "DVB-S/S2"
	case 1:
		return "DVB-C"
	case 2:
		return "DVB-T/T2"
	case 3:
		return "ATSC"
	default:
		return fmt.Sprintf("type-%d", raw)
	}
}

func findExternalOwner(procRoot, devicePath string) externalOwner {
	return findExternalOwners(procRoot, []string{devicePath})[devicePath]
}

func findExternalOwners(procRoot string, devicePaths []string) map[string]externalOwner {
	return findExternalOwnersAt(procRoot, devicePaths, maxProcPIDEntries, maxProcFDLinks)
}

func findExternalOwnersAt(procRoot string, devicePaths []string, pidLimit, fdLimit int) map[string]externalOwner {
	owners, _ := findExternalOwnersAtContext(context.Background(), procRoot, devicePaths, pidLimit, fdLimit)
	return owners
}

func findExternalOwnersContext(ctx context.Context, procRoot string, devicePaths []string) (map[string]externalOwner, error) {
	return findExternalOwnersAtContext(ctx, procRoot, devicePaths, maxProcPIDEntries, maxProcFDLinks)
}

func findExternalOwnersAtContext(ctx context.Context, procRoot string, devicePaths []string, pidLimit, fdLimit int) (map[string]externalOwner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owners := make(map[string]externalOwner, len(devicePaths))
	targets := make(map[string]os.FileInfo, len(devicePaths))
	for _, devicePath := range devicePaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, duplicate := targets[devicePath]; duplicate {
			continue
		}
		targetInfo, err := os.Stat(devicePath)
		if err != nil {
			owners[devicePath] = externalOwner{warning: fmt.Sprintf("external owner unknown: stat frontend: %v", err)}
			continue
		}
		targets[devicePath] = targetInfo
	}
	if len(targets) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return owners, nil
	}

	uncertainty := ""
	recordUncertainty := func(warning string) {
		if uncertainty == "" {
			uncertainty = warning
		}
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pids, pidExhausted, err := readNumericDir(procRoot, pidLimit)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if err != nil {
		recordUncertainty(fmt.Sprintf("external owner unknown: inspect proc: %v", err))
		pids = nil
	}
	if pidExhausted {
		recordUncertainty(fmt.Sprintf("external owner unknown: proc PID limit %d exhausted", pidLimit))
	}

	resolved := make(map[string]bool, len(targets))
	fdLinks := 0
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(resolved) == len(targets) {
			break
		}
		remaining := fdLimit - fdLinks
		if remaining <= 0 {
			recordUncertainty(fmt.Sprintf("external owner unknown: proc fd limit %d exhausted", fdLimit))
			break
		}

		fdRoot := filepath.Join(procRoot, strconv.Itoa(pid), "fd")
		fds, fdExhausted, err := readProcFDDir(pid, fdRoot, remaining)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if err != nil {
			recordUncertainty(fmt.Sprintf("external owner unknown: inspect %s: %v", fdRoot, err))
			continue
		}
		fdLinks += len(fds)
		if fdExhausted {
			recordUncertainty(fmt.Sprintf("external owner unknown: proc fd limit %d exhausted", fdLimit))
		}

		for _, fd := range fds {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fdPath := filepath.Join(fdRoot, strconv.Itoa(fd))
			fdInfo, err := os.Stat(fdPath)
			if err != nil {
				recordUncertainty(fmt.Sprintf("external owner unknown: inspect %s: %v", fdPath, err))
				continue
			}

			matches := make([]string, 0, 1)
			for devicePath, targetInfo := range targets {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				if !resolved[devicePath] && os.SameFile(targetInfo, fdInfo) {
					matches = append(matches, devicePath)
				}
			}
			if len(matches) == 0 {
				continue
			}

			commPath := filepath.Join(procRoot, strconv.Itoa(pid), "comm")
			payload, commErr := os.ReadFile(commPath)
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			command := strings.TrimSpace(string(payload))
			for _, devicePath := range matches {
				owner := externalOwner{pid: pid, command: command}
				switch {
				case commErr != nil:
					owner.warning = fmt.Sprintf("external owner command unknown: read %s: %v", commPath, commErr)
				case command == "":
					owner.warning = fmt.Sprintf("external owner command unknown: %s is empty", commPath)
				}
				if uncertainty != "" {
					owner.warning = appendWarning(owner.warning, lowerOwnerUncertaintyWarning(uncertainty))
				}
				owners[devicePath] = owner
				resolved[devicePath] = true
			}
		}
	}

	for devicePath := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if resolved[devicePath] {
			continue
		}
		owners[devicePath] = externalOwner{free: uncertainty == "", warning: uncertainty}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return owners, nil
}

func lowerOwnerUncertaintyWarning(uncertainty string) string {
	detail := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(uncertainty), "external owner unknown:"))
	if detail == "" {
		detail = "an earlier proc entry could not be inspected"
	}
	return "lower external ownership could not be ruled out: " + detail
}

func readNumericDir(path string, limit int) ([]int, bool, error) {
	if limit < 1 {
		return nil, true, nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()
	return readNumericDirFromOpenDir(dir, limit, -1)
}

func readProcFDDir(pid int, path string, limit int) ([]int, bool, error) {
	return readProcFDDirAt(pid, path, limit, os.Open)
}

func readProcFDDirAt(pid int, path string, limit int, openDir func(string) (*os.File, error)) ([]int, bool, error) {
	if limit < 1 {
		return nil, true, nil
	}
	dir, err := openDir(path)
	if err != nil {
		return nil, false, err
	}
	defer dir.Close()

	excludedFD := -1
	if pid == os.Getpid() {
		openedInfo, openedErr := dir.Stat()
		currentInfo, currentErr := os.Stat("/proc/self/fd")
		if openedErr == nil && currentErr == nil && os.SameFile(openedInfo, currentInfo) {
			excludedFD = int(dir.Fd())
		}
	}
	return readNumericDirFromOpenDir(dir, limit, excludedFD)
}

func readNumericDirFromOpenDir(dir *os.File, limit, excludedFD int) ([]int, bool, error) {
	if limit < 1 {
		return nil, true, nil
	}
	values := make([]int, 0, limit+1)
	for {
		batch, readErr := dir.ReadDir(256)
		for _, entry := range batch {
			value, err := strconv.Atoi(entry.Name())
			if err != nil || value < 0 {
				continue
			}
			if value == excludedFD {
				continue
			}
			values = append(values, value)
			if len(values) > limit {
				sort.Ints(values)
				return values[:limit], true, nil
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, false, readErr
		}
		if len(batch) == 0 {
			break
		}
	}

	sort.Ints(values)
	return values, false, nil
}

func ior(t, nr uintptr, size uintptr) uintptr {
	return ((iocRead) << iocDirShift) | (size << iocSizeShift) | (t << iocTypeShift) | (nr << iocNRShift)
}
