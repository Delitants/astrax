// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"fmt"
	"time"

	"astrax/internal/epg"
)

// ParseEITSections parses raw EIT sections into epg.Programme structs.
// Each section is a complete EIT section (including CRC).
func ParseEITSections(sections [][]byte) []epg.Programme {
	var programmes []epg.Programme
	for _, sec := range sections {
		if len(sec) < 14 {
			continue
		}
		serviceID := (int(sec[3]) << 8) | int(sec[4])
		_ = (int(sec[8]) << 8) | int(sec[9])  // transportStreamID
		_ = (int(sec[10]) << 8) | int(sec[11]) // originalNetworkID

		sectionLen := int(((uint16(sec[1])&0x0F)<<8)|uint16(sec[2])) + 3
		if sectionLen > len(sec) {
			sectionLen = len(sec)
		}

		offset := 14
		for offset+12 <= sectionLen-4 {
			_ = (int(sec[offset]) << 8) | int(sec[offset+1]) // eventID
			startTime := parseDVBTimestamp(sec[offset+2 : offset+7])
			duration := parseDVBDuration(sec[offset+7 : offset+10])
			descLen := ((int(sec[offset+10]) & 0x0F) << 8) | int(sec[offset+11])
			descEnd := offset + 12 + descLen
			if descEnd > sectionLen-4 {
				descEnd = sectionLen - 4
			}

			var title, lang string
			d := offset + 12
			for d+2 <= descEnd {
				tag := sec[d]
				length := int(sec[d+1])
				if d+2+length > descEnd {
					break
				}
				switch tag {
				case 0x4D:
					title, lang = parseShortEventDescriptor(sec[d+2 : d+2+length])
				case 0x4E:
					// extended_event_descriptor — skip for now
				}
				d += 2 + length
			}

			stopTime := startTime.Add(duration)
			programmes = append(programmes, epg.Programme{
				Channel: fmt.Sprintf("0x%04X", serviceID),
				Start:   startTime.Format("20060102150405 -0700"),
				Stop:    stopTime.Format("20060102150405 -0700"),
				Title:   []epg.Title{{Lang: lang, Value: title}},
			})

			offset = descEnd
		}
	}
	return programmes
}

// parseDVBTimestamp converts MJD+BCD time to Go time.Time in UTC.
//
// The algorithm follows ETSI EN 300 468 Annex C for Modified Julian Date conversion:
//   - 15078.2 is the MJD offset for 1 Jan 1900 (the DVB epoch base).
//   - 365.25 accounts for the average length of a Gregorian year.
//   - 30.6001 accounts for the average month length in the Julian calendar
//     (where months 14/15 correspond to Jan/Feb of the next year).
func parseDVBTimestamp(data []byte) time.Time {
	if len(data) < 5 {
		return time.Time{}
	}
	mjd := (int(data[0]) << 8) | int(data[1])
	year := int((float64(mjd) - 15078.2) / 365.25)
	month := int((float64(mjd) - 14956.1 - float64(int(float64(year)*365.25))) / 30.6001)
	day := mjd - 14956 - int(float64(int(float64(year)*365.25))) - int(float64(int(float64(month)*30.6001)))
	if month == 14 || month == 15 {
		year++
		month -= 12
	}
	year += 1900
	month--

	hour := bcdToInt(data[2])
	min := bcdToInt(data[3])
	sec := bcdToInt(data[4])

	return time.Date(year, time.Month(month), day, hour, min, sec, 0, time.UTC)
}

// parseDVBDuration converts BCD HH:MM:SS to time.Duration.
func parseDVBDuration(data []byte) time.Duration {
	if len(data) < 3 {
		return 0
	}
	hour := bcdToInt(data[0])
	min := bcdToInt(data[1])
	sec := bcdToInt(data[2])
	return time.Duration(hour)*time.Hour + time.Duration(min)*time.Minute + time.Duration(sec)*time.Second
}

func bcdToInt(b byte) int {
	hi := int(b >> 4)
	lo := int(b & 0x0F)
	if hi > 9 { hi = 0 }
	if lo > 9 { lo = 0 }
	return hi*10 + lo
}

func parseShortEventDescriptor(data []byte) (string, string) {
	if len(data) < 4 {
		return "", ""
	}
	lang := string(data[0:3])
	nameLen := int(data[3])
	if 4+nameLen > len(data) {
		return "", lang
	}
	name := string(data[4 : 4+nameLen])
	return sanitizeDVBText(name), lang
}
