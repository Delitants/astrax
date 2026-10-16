// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package streamer

import (
	"strconv"
	"strings"
)

type customRoute struct {
	publication pathPublication
	base        string
	playlist    bool
}

// Exact aliases and reverse segment claims cover the infinite numeric segment
// domain without enumerating segments or scanning configured paths on requests.
type pathNamespace struct {
	aliases        map[string]customRoute
	segmentAliases map[string]map[string]pathPublication
}

// OutputPathsConflict compares normalized paths returned by ValidateOutputPath
// using the same alias/segment namespace as runtime registration. It performs
// no registration, resource preparation, or I/O.
func OutputPathsConflict(left, right string) bool {
	var namespace pathNamespace
	namespace.add(left, pathPublication{streamID: "comparison", generation: 1})
	return namespace.conflict(right, pathPublication{}) != ""
}

func customAliases(base string) [3]string {
	return [3]string{base, base + ".ts", base + ".m3u8"}
}

func numericSegmentBase(path string) (string, bool) {
	if !strings.HasSuffix(path, ".ts") {
		return "", false
	}
	stem := strings.TrimSuffix(path, ".ts")
	index := strings.LastIndexByte(stem, '_')
	if index <= 0 {
		return "", false
	}
	number := stem[index+1:]
	if number == "" || len(number) > 1 && number[0] == '0' {
		return "", false
	}
	for _, digit := range number {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	if _, err := strconv.Atoi(number); err != nil {
		return "", false
	}
	return stem[:index], true
}

func (ns *pathNamespace) conflict(base string, allowed pathPublication) string {
	if base == "" {
		return ""
	}
	for _, alias := range customAliases(base) {
		if route, ok := ns.aliases[alias]; ok && route.publication != allowed {
			return route.publication.streamID
		}
		if parent, ok := numericSegmentBase(alias); ok {
			if route, exists := ns.aliases[parent]; exists && route.base == parent && route.publication != allowed {
				return route.publication.streamID
			}
		}
	}
	for _, owner := range ns.segmentAliases[base] {
		if owner != allowed {
			return owner.streamID
		}
	}
	return ""
}

func (ns *pathNamespace) add(base string, publication pathPublication) {
	if base == "" {
		return
	}
	if ns.aliases == nil {
		ns.aliases = make(map[string]customRoute)
		ns.segmentAliases = make(map[string]map[string]pathPublication)
	}
	for i, alias := range customAliases(base) {
		ns.aliases[alias] = customRoute{publication: publication, base: base, playlist: i == 2}
		if parent, ok := numericSegmentBase(alias); ok {
			if ns.segmentAliases[parent] == nil {
				ns.segmentAliases[parent] = make(map[string]pathPublication)
			}
			ns.segmentAliases[parent][alias] = publication
		}
	}
}

func (ns *pathNamespace) remove(base string, publication pathPublication) {
	if base == "" {
		return
	}
	for _, alias := range customAliases(base) {
		if route, ok := ns.aliases[alias]; ok && route.publication == publication {
			delete(ns.aliases, alias)
		}
		if parent, ok := numericSegmentBase(alias); ok {
			claims := ns.segmentAliases[parent]
			if claims[alias] == publication {
				delete(claims, alias)
				if len(claims) == 0 {
					delete(ns.segmentAliases, parent)
				}
			}
		}
	}
}

func (st *Streamer) publishPathLocked(base string, publication pathPublication) {
	if base != "" {
		st.customPaths[base] = publication
		st.publishedPaths.add(base, publication)
	}
}
