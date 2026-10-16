// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import "time"

func runEITCollector(interval time.Duration, collect func(), stop <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			collect()
		}
	}
}
