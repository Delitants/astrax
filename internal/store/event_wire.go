// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"astrax/internal/model"
)

var errEventPayload = errors.New("unsupported or oversized event payload")

// A wire limit is not a reason to erase the typed observer contract. These
// acyclic model snapshots have audited clone helpers; they are NEVER enqueued.
// Unsupported Operation.Result graphs are omitted, not retained or evaluated.
func rejectedEventObserver(payload any, depth int) any {
	if depth > 32 {
		return nil
	}
	v := reflect.ValueOf(payload)
	if v.IsValid() && v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		copy := rejectedEventObserver(v.Elem().Interface(), depth+1)
		if copy == nil {
			return nil
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(reflect.ValueOf(copy))
		return out.Interface()
	}
	switch x := payload.(type) {
	case model.Stream:
		return cloneStream(x)
	case model.StreamRuntime:
		return cloneStreamRuntime(x)
	case model.DVBCard:
		return cloneDVBCard(x)
	case dvbCardOwnership:
		return cloneDVBCardOwnership(x)
	case model.DVBGroup:
		return x
	case model.DVBInvalidation:
		return x
	case model.Operation:
		out := cloneDVBOperation(x)
		out.Result = nil
		budget := model.MaxEventFrameBytes
		if copy, err := copyEventValue(reflect.ValueOf(x.Result), &budget, 0); err == nil && copy.IsValid() {
			out.Result = copy.Interface()
		}
		return out
	}
	return nil
}

// No payload methods are invoked here. Explicitly known structs and ordinary
// JSON values are copied with a byte/node/depth budget before any marshaling.
// In particular Operation.Result is not permission to retain/encode arbitrary Go.
func copyEventValue(v reflect.Value, budget *int, depth int) (reflect.Value, error) {
	*budget--
	if *budget < 0 || depth > 32 {
		return reflect.Value{}, errEventPayload
	}
	if !v.IsValid() {
		return v, nil
	}
	if v.Type() == reflect.TypeOf(time.Time{}) {
		return reflect.ValueOf(v.Interface().(time.Time).UTC()), nil
	}
	if v.Type() == reflect.TypeOf(json.RawMessage{}) {
		data := v.Interface().(json.RawMessage)
		if len(data) > *budget || !json.Valid(data) {
			return reflect.Value{}, errEventPayload
		}
		var plain any
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		if err := d.Decode(&plain); err != nil {
			return reflect.Value{}, errEventPayload
		}
		// Keep RawMessage's typed observer contract only after auditing its tree.
		if _, err := copyEventValue(reflect.ValueOf(plain), budget, depth+1); err != nil {
			return reflect.Value{}, err
		}
		return reflect.ValueOf(append(json.RawMessage(nil), data...)), nil
	}
	if v.Type().PkgPath() != "" && v.Type() != reflect.TypeOf(json.Number("")) && !knownEventStruct(v.Type()) {
		return reflect.Value{}, errEventPayload
	}
	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		x, err := copyEventValue(v.Elem(), budget, depth+1)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type()).Elem()
		out.Set(x)
		return out, nil
	case reflect.Pointer:
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		x, err := copyEventValue(v.Elem(), budget, depth+1)
		if err != nil {
			return reflect.Value{}, err
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(x)
		return out, nil
	case reflect.Struct:
		if !knownEventStruct(v.Type()) {
			return reflect.Value{}, errEventPayload
		}
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.NumField(); i++ {
			if !out.Field(i).CanSet() {
				return reflect.Value{}, errEventPayload
			}
			x, err := copyEventValue(v.Field(i), budget, depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Field(i).Set(x)
		}
		return out, nil
	case reflect.Map:
		if v.Type().Key() != reflect.TypeOf("") || v.Len() > *budget {
			return reflect.Value{}, errEventPayload
		}
		if v.IsNil() {
			return reflect.Zero(v.Type()), nil
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key, err := copyEventValue(iter.Key(), budget, depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			x, err := copyEventValue(iter.Value(), budget, depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			out.SetMapIndex(key, x)
		}
		return out, nil
	case reflect.Slice, reflect.Array:
		if v.Len() > *budget {
			return reflect.Value{}, errEventPayload
		}
		var out reflect.Value
		if v.Kind() == reflect.Slice {
			if v.IsNil() {
				return reflect.Zero(v.Type()), nil
			}
			out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		} else {
			out = reflect.New(v.Type()).Elem()
		}
		for i := 0; i < v.Len(); i++ {
			x, err := copyEventValue(v.Index(i), budget, depth+1)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(i).Set(x)
		}
		return out, nil
	case reflect.String:
		*budget -= v.Len()
		if *budget < 0 {
			return reflect.Value{}, errEventPayload
		}
		out := reflect.New(v.Type()).Elem()
		out.SetString(strings.Clone(v.String()))
		return out, nil
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return v, nil
	default:
		return reflect.Value{}, errEventPayload
	}
}

func knownEventStruct(t reflect.Type) bool {
	switch t {
	case reflect.TypeOf(model.Stream{}), reflect.TypeOf(model.StreamRuntime{}), reflect.TypeOf(model.DVBGroup{}), reflect.TypeOf(model.DVBInvalidation{}),
		reflect.TypeOf(model.DVBCard{}), reflect.TypeOf(model.DVBCardConfig{}), reflect.TypeOf(model.DVBCardApplication{}), reflect.TypeOf(dvbCardOwnership{}),
		reflect.TypeOf(model.DVBStreamConfig{}), reflect.TypeOf(model.DVBAdapterPolicy{}), reflect.TypeOf(model.DVBSignal{}), reflect.TypeOf(model.DVBPlacementRuntime{}),
		reflect.TypeOf(model.AdapterLNBConfig{}), reflect.TypeOf(model.AdapterAdvancedConfig{}), reflect.TypeOf(model.Service{}),
		reflect.TypeOf(model.Operation{}), reflect.TypeOf(model.BulkDVBStreamItemResult{}), reflect.TypeOf(model.DVBScanResult{}), reflect.TypeOf(model.DVBScanRequest{}):
		return true
	}
	return false
}

type eventRuntime struct {
	model.StreamRuntime
	Signal    *model.DVBSignal           `json:"signal"`
	Placement *model.DVBPlacementRuntime `json:"placement"`
	LastError string                     `json:"last_error"`
}

func safeEventError(value, message string) string {
	if value != "" {
		return message
	}
	return ""
}

func eventRuntimeValue(v model.StreamRuntime) eventRuntime {
	return eventRuntime{v, v.Signal, v.Placement, safeEventError(v.LastError, "runtime unavailable")}
}

type eventApplication struct {
	model.DVBCardApplication
	AppliedConfig *model.DVBCardConfig `json:"applied_config"`
	Error         string               `json:"error"`
	Reason        string               `json:"reason"`
}

func eventApplicationValue(v *model.DVBCardApplication) *eventApplication {
	if v == nil {
		return nil
	}
	return &eventApplication{*v, v.AppliedConfig, safeEventError(v.Error, "card application failed"), safeEventError(v.Reason, "card application pending")}
}

// Dynamic data cannot smuggle a diagnostic-bearing model past its projection.
// The input has already passed the bounded copier, so this walk is also bounded.
func plainEventData(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	if v.Type() == reflect.TypeOf(json.RawMessage{}) || v.Type() == reflect.TypeOf(json.Number("")) {
		return true
	}
	if v.Type().PkgPath() != "" {
		return false
	}
	switch v.Kind() {
	case reflect.Interface:
		return v.IsNil() || plainEventData(v.Elem())
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if !plainEventData(iter.Value()) {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if !plainEventData(v.Index(i)) {
				return false
			}
		}
		return true
	case reflect.Bool, reflect.String, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

type eventOwnership struct {
	Application      *eventApplication      `json:"application"`
	CurrentTransport *model.DVBStreamConfig `json:"current_transport"`
	ActiveSessions   int                    `json:"active_sessions"`
	ActiveStreams    int                    `json:"active_streams"`
	Signal           *model.DVBSignal       `json:"signal"`
	LastError        string                 `json:"last_error"`
}

// prepareEventPayload returns independent observer and wire representations.
// Only the immutable JSON value ever reaches subscriber queues.
func prepareEventPayload(kind string, payload any) (any, model.EventWirePayload, error) {
	budget := model.MaxEventFrameBytes
	v, err := copyEventValue(reflect.ValueOf(payload), &budget, 0)
	if err != nil {
		return rejectedEventObserver(payload, 0), model.EventWirePayload{}, err
	}
	var owned any
	if v.IsValid() {
		owned = v.Interface()
	}
	value := owned
	// Accept pointers to known data while retaining their type for observers.
	for p := reflect.ValueOf(value); p.IsValid() && p.Kind() == reflect.Pointer; p = reflect.ValueOf(value) {
		if p.IsNil() {
			value = nil
			break
		}
		value = p.Elem().Interface()
	}
	mode, field := "invalidate", "data"
	var outward any = value
	switch x := value.(type) {
	case model.StreamRuntime:
		mode, field = "runtime", "runtime"
		outward = eventRuntimeValue(x)
	case model.Stream:
		mode, field = "replace", "resource"
		outward = struct {
			model.Stream
			Runtime eventRuntime `json:"runtime"`
		}{x, eventRuntimeValue(x.Runtime)}
	case dvbCardOwnership:
		mode, field = "ownership", "ownership"
		outward = eventOwnership{eventApplicationValue(x.Application), x.CurrentTransport, x.ActiveSessions, x.ActiveStreams, x.Signal, safeEventError(x.LastError, "card unavailable")}
	case model.DVBCard:
		mode, field = "replace", "resource"
		outward = struct {
			model.DVBCard
			Application      *eventApplication      `json:"application"`
			CurrentTransport *model.DVBStreamConfig `json:"current_transport"`
			Signal           *model.DVBSignal       `json:"signal"`
			LastError        string                 `json:"last_error"`
			Warning          string                 `json:"warning"`
		}{x, eventApplicationValue(x.Application), x.CurrentTransport, x.Signal, safeEventError(x.LastError, "card unavailable"), safeEventError(x.Warning, "card requires attention")}
	case model.DVBGroup:
		mode, field = "replace", "resource"
	case model.DVBInvalidation:
		data, err := json.Marshal(struct {
			Mode string `json:"mode"`
			model.DVBInvalidation
		}{"invalidate", x})
		if err != nil {
			return owned, model.EventWirePayload{}, err
		}
		wire, err := model.NewEventWirePayload(data)
		return owned, wire, err
	case model.Operation:
		if !plainEventData(reflect.ValueOf(x.Result)) {
			return owned, model.EventWirePayload{}, errEventPayload
		}
		mode, field = "replace", "resource"
		// Clone the error-bearing slice again: owned remains the diagnostic observer copy.
		x.StreamResults = append([]model.BulkDVBStreamItemResult(nil), x.StreamResults...)
		x.Error = safeEventError(x.Error, "operation failed")
		x.Message = safeEventError(x.Message, "operation status updated")
		for i := range x.StreamResults {
			x.StreamResults[i].Error = safeEventError(x.StreamResults[i].Error, "operation failed")
		}
		outward = x
	default:
		if !plainEventData(reflect.ValueOf(value)) {
			return owned, model.EventWirePayload{}, errEventPayload
		}
	}
	if strings.HasSuffix(kind, ".removed") {
		if value != nil {
			return owned, model.EventWirePayload{}, errEventPayload
		}
		mode, field = "remove", ""
	}
	wrapper := map[string]any{"mode": mode}
	if field != "" {
		wrapper[field] = outward
	}
	data, err := json.Marshal(wrapper)
	if err != nil {
		return owned, model.EventWirePayload{}, err
	}
	wire, err := model.NewEventWirePayload(data)
	return owned, wire, err
}
