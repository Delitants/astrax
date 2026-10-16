// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"time"

	"astrax/internal/model"
)

func openCCcamSession(profile model.Softcam) (session, time.Duration, error) {
	return openCCcamSessionContext(context.Background(), profile)
}
