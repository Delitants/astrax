// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"bytes"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
)

func TestEmbeddedDescramblingAssets(t *testing.T) {
	for _, name := range []string{"dvb-descrambling.js", "dvb-editor.js", "dvb-streams.js", "dvb-stream-query.js", "index.html", "dvb-management.css", "app.js"} {
		embedded, err := webFS.ReadFile("web/" + name)
		if err != nil {
			t.Fatal(err)
		}
		source, err := os.ReadFile("web/" + name)
		if err != nil || len(source) == 0 || !bytes.Equal(embedded, source) {
			t.Fatalf("embedded Stage C asset differs from source: %s (%v)", name, err)
		}
	}
}

func TestEmbeddedWebAssetsExcludeTemporaryFiles(t *testing.T) {
	err := fs.WalkDir(webFS, "web", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		base := path.Base(name)
		if strings.HasSuffix(base, ".tmp") || strings.Contains(base, ".tmp.") {
			t.Errorf("temporary file is exposed by the embedded web bundle: %s", name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
