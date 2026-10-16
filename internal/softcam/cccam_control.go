// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import "time"

const cccamLivenessBudget = 4 * time.Second

// This mode interpreter is shared by login and the session reader. It does not
// retain server metadata or derive keys for unsupported challenge families.
type cccamControl struct{ plain bool }

func (c *cccamControl) interpret(frame cccamFrame) (*cccamFrame, error) {
	if frame.Flags != 0 {
		return nil, protocolError("unsupported_protocol", nil)
	}
	switch frame.Command {
	case 8:
		if len(frame.Payload) != 72 {
			return nil, protocolError("unsupported_protocol", nil)
		}
		c.plain = true
		return nil, nil
	case 5:
		if len(frame.Payload) != 0 && !(c.plain && len(frame.Payload) == 256) {
			return nil, protocolError("unsupported_protocol", nil)
		}
		return &cccamFrame{Command: 5, Payload: append([]byte(nil), frame.Payload...)}, nil
	default:
		return nil, protocolError("unsupported_protocol", nil)
	}
}
