//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var dmxSetFilter = iow(ioctlTypeDVB, 43, unsafe.Sizeof(dmxSctFilterParams{}))

const (
	dmxCheckCRC       = 0x01
	dmxOneshot        = 0x02
	dmxImmediateStart = 0x04
)

type dmxSctFilterParams struct {
	PID            uint16
	Filter         [16]uint8
	Mask           [16]uint8
	Mode           [16]uint8
	Timeout        uint32
	Flags          uint32
}

func (s *linuxSession) ScanServices() ([]Service, error) {
	demuxPath := filepath.Join("/dev/dvb", fmt.Sprintf("adapter%d", s.cfg.Adapter), fmt.Sprintf("demux%d", s.cfg.Frontend))
	return scanServices(demuxPath, readSection, readAllSections, readSectionsRaw)
}

// scanServices preserves table metadata; device access is confined to the supplied readers.
func scanServices(
	demuxPath string,
	readOne func(string, uint16, uint8, int) ([]byte, error),
	readAll func(string, uint16, uint8, int) ([][]byte, error),
	readRaw func(string, uint16, uint8, int) ([][]byte, error),
) ([]Service, error) {
	// Read PAT to discover program numbers and PMT PIDs
	pat, err := readOne(demuxPath, 0x0000, 0x00, 3000)
	if err != nil {
		return nil, fmt.Errorf("read PAT: %w", err)
	}
	programs := parsePAT(pat)
	if len(programs) == 0 {
		return nil, nil
	}

	var services []Service
	for _, prog := range programs {
		if prog.Number == 0 {
			continue // network PID
		}
		pmt, err := readOne(demuxPath, uint16(prog.PMT_PID), 0x02, 3000)
		if err != nil {
			continue
		}
		svc := parsePMT(pmt, prog.Number)
		if svc != nil {
			services = append(services, *svc)
		}
	}

	// Read all SDT sections for service names
	sdtSections, err := readAll(demuxPath, 0x0011, 0x42, 3000)
	if err == nil {
		names := make(map[int]string)
		for _, sec := range sdtSections {
			for sid, name := range parseSDT(sec) {
				names[sid] = name
			}
		}
		for i := range services {
			if name, ok := names[services[i].SID]; ok {
				services[i].Name = name
			}
		}
	}

	// Read EIT sections to detect per-service EPG (PID 0x12, table_id 0x4E).
	// EIT uses readSectionsRaw because multiple services share the same table_id
	// with overlapping section_numbers — readAllSections would overwrite them.
	eitSections, err := readRaw(demuxPath, 0x0012, 0x4E, 3000)
	if err == nil {
		epgServices := make(map[int]bool)
		for _, sec := range eitSections {
			// EIT section with section_syntax_indicator=1 has service_id at bytes 3-4.
			// Minimum header is 14 bytes + 4 bytes CRC = 18 bytes.
			// A section with actual events must be > 18 bytes.
			if len(sec) > 18 && (sec[1]&0x80) != 0 {
				sid := (int(sec[3]) << 8) | int(sec[4])
				epgServices[sid] = true
			}
		}
		for i := range services {
			if epgServices[services[i].SID] {
				services[i].HasEPG = true
			}
		}
	}

	return services, nil
}

func readSection(demuxPath string, pid uint16, tableID uint8, timeoutMs int) ([]byte, error) {
	fd, err := syscall.Open(demuxPath, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open demux: %w", err)
	}

	params := dmxSctFilterParams{
		PID:     pid,
		Timeout: uint32(timeoutMs),
		Flags:   dmxImmediateStart | dmxCheckCRC,
	}
	params.Filter[0] = tableID
	params.Mask[0] = 0xFF

	if err := ioctlPtr(fd, dmxSetFilter, unsafe.Pointer(&params)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("DMX_SET_FILTER: %w", err)
	}

	type readResult struct {
		data []byte
		err  error
	}

	done := make(chan readResult, 1)
	go func() {
		defer syscall.Close(fd)
		buf := make([]byte, 4096)
		deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					if time.Now().After(deadline) {
						done <- readResult{err: fmt.Errorf("section read timeout")}
						return
					}
					time.Sleep(50 * time.Millisecond)
					continue
				}
				done <- readResult{err: err}
				return
			}
			if n > 0 {
				done <- readResult{data: append([]byte(nil), buf[:n]...)}
				return
			}
			done <- readResult{err: fmt.Errorf("read returned 0 bytes")}
			return
		}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		// Diagnostic: some drivers return raw TS packets instead of sections.
		logSectionBytes(pid, tableID, r.data)
		return r.data, nil
	case <-time.After(time.Duration(timeoutMs+2000) * time.Millisecond):
		// Some drivers ignore O_NONBLOCK on demux fds. Force-close the fd
		// to unblock the goroutine so it does not leak and hold the frontend.
		syscall.Close(fd)
		return nil, fmt.Errorf("section read timeout")
	}
}

func logSectionBytes(pid uint16, tableID uint8, data []byte) {
	if len(data) == 0 {
		return
	}
	if data[0] == 0x47 {
		log.Printf("SCAN DIAG: PID 0x%04X table 0x%02X returned TS packet (sync=0x47), NOT a section! len=%d", pid, tableID, len(data))
		return
	}
	if data[0] != tableID {
		log.Printf("SCAN DIAG: PID 0x%04X table 0x%02X first byte mismatch: got 0x%02X, want 0x%02X len=%d", pid, tableID, data[0], tableID, len(data))
		return
	}
	n := 20
	if len(data) < n {
		n = len(data)
	}
	var hexStr strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&hexStr, "%02X ", data[i])
	}
	log.Printf("SCAN DIAG: PID 0x%04X table 0x%02X len=%d first %d bytes: %s", pid, tableID, len(data), n, hexStr.String())
}

// readAllSections opens the demux once, sets a filter, and reads every section
// of the given table_id on the given PID until all sections (0..last_section_number)
// have been received.
func readAllSections(demuxPath string, pid uint16, tableID uint8, timeoutMs int) ([][]byte, error) {
	fd, err := syscall.Open(demuxPath, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open demux: %w", err)
	}

	params := dmxSctFilterParams{
		PID:     pid,
		Timeout: uint32(timeoutMs),
		Flags:   dmxImmediateStart | dmxCheckCRC,
	}
	params.Filter[0] = tableID
	params.Mask[0] = 0xFF

	if err := ioctlPtr(fd, dmxSetFilter, unsafe.Pointer(&params)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("DMX_SET_FILTER: %w", err)
	}

	type readResult struct {
		sections [][]byte
		err      error
	}

	done := make(chan readResult, 1)
	go func() {
		defer syscall.Close(fd)
		deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
		sections := make(map[uint8][]byte)
		var lastSectionNumber uint8 = 0xFF
		buf := make([]byte, 4096)

		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					if time.Now().After(deadline) {
						break
					}
					time.Sleep(20 * time.Millisecond)
					continue
				}
				done <- readResult{err: err}
				return
			}
			if n < 8 || buf[0] != tableID {
				continue
			}
			secNum := buf[6]
			lastSec := buf[7]
			if lastSec < lastSectionNumber {
				lastSectionNumber = lastSec
			}
			sections[secNum] = append([]byte(nil), buf[:n]...)
			if uint8(len(sections)-1) >= lastSectionNumber {
				break
			}
			if time.Now().After(deadline) {
				break
			}
		}

		if len(sections) == 0 {
			done <- readResult{err: fmt.Errorf("section read timeout")}
			return
		}

		result := make([][]byte, 0, len(sections))
		for i := uint8(0); i <= lastSectionNumber; i++ {
			if sec, ok := sections[i]; ok {
				result = append(result, sec)
			}
		}
		done <- readResult{sections: result}
	}()

	select {
	case r := <-done:
		return r.sections, r.err
	case <-time.After(time.Duration(timeoutMs+2000) * time.Millisecond):
		syscall.Close(fd)
		return nil, fmt.Errorf("section read timeout")
	}
}

// readSectionsRaw opens the demux once, sets a filter, and reads every section
// of the given table_id on the given PID until the timeout expires.
// Unlike readAllSections, it does NOT deduplicate by section_number — it collects
// all raw sections in a slice. Use this for tables like EIT where multiple
// logical tables (one per service_id) share the same table_id.
func readSectionsRaw(demuxPath string, pid uint16, tableID uint8, timeoutMs int) ([][]byte, error) {
	fd, err := syscall.Open(demuxPath, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open demux: %w", err)
	}

	params := dmxSctFilterParams{
		PID:     pid,
		Timeout: uint32(timeoutMs),
		Flags:   dmxImmediateStart | dmxCheckCRC,
	}
	params.Filter[0] = tableID
	params.Mask[0] = 0xFF

	if err := ioctlPtr(fd, dmxSetFilter, unsafe.Pointer(&params)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("DMX_SET_FILTER: %w", err)
	}

	type readResult struct {
		sections [][]byte
		err      error
	}

	done := make(chan readResult, 1)
	go func() {
		defer syscall.Close(fd)
		deadline := time.Now().Add(time.Duration(timeoutMs) * time.Millisecond)
		var sections [][]byte
		buf := make([]byte, 4096)

		for {
			n, err := syscall.Read(fd, buf)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
					if time.Now().After(deadline) {
						break
					}
					time.Sleep(20 * time.Millisecond)
					continue
				}
				done <- readResult{err: err}
				return
			}
			if n >= 8 && buf[0] == tableID {
				sections = append(sections, append([]byte(nil), buf[:n]...))
			}
			if time.Now().After(deadline) {
				break
			}
		}

		if len(sections) == 0 {
			done <- readResult{err: fmt.Errorf("section read timeout")}
			return
		}
		done <- readResult{sections: sections}
	}()

	select {
	case r := <-done:
		return r.sections, r.err
	case <-time.After(time.Duration(timeoutMs+2000) * time.Millisecond):
		syscall.Close(fd)
		return nil, fmt.Errorf("section read timeout")
	}
}

// parsePAT extracts program number -> PMT PID mappings from a PAT section.
func parsePAT(data []byte) []struct {
	Number  int
	PMT_PID int
} {
	if len(data) < 8 {
		return nil
	}
	sectionLen := int(((uint16(data[1])&0x0F)<<8)|uint16(data[2])) + 3
	if sectionLen > len(data) {
		sectionLen = len(data)
	}

	var programs []struct {
		Number  int
		PMT_PID int
	}
	offset := 8
	for offset+4 <= sectionLen-4 { // leave 4 bytes for CRC
		progNum := (int(data[offset]) << 8) | int(data[offset+1])
		pid := ((int(data[offset+2]) & 0x1F) << 8) | int(data[offset+3])
		programs = append(programs, struct {
			Number  int
			PMT_PID int
		}{Number: progNum, PMT_PID: pid})
		offset += 4
	}
	return programs
}

// parsePMT extracts service info from a PMT section.
func parsePMT(data []byte, programNumber int) *Service {
	if len(data) < 12 {
		log.Printf("parsePMT: sid=%d data too short len=%d", programNumber, len(data))
		return nil
	}
	sectionLen := int(((uint16(data[1])&0x0F)<<8)|uint16(data[2])) + 3
	if sectionLen > len(data) {
		sectionLen = len(data)
	}
	actualProgNum := (int(data[3]) << 8) | int(data[4])
	pcrPID := ((int(data[8]) & 0x1F) << 8) | int(data[9])
	programInfoLen := ((int(data[10]) & 0x0F) << 8) | int(data[11])

	offset := 12 + programInfoLen
	svc := &Service{
		SID:     programNumber,
		PCR_PID: pcrPID,
		Name:    fmt.Sprintf("Service %d", programNumber),
	}

	log.Printf("parsePMT: sid=%d sectionLen=%d progNum=%d pcrPID=%d programInfoLen=%d streamCount=%d", programNumber, sectionLen, actualProgNum, pcrPID, programInfoLen, (sectionLen-4-offset)/5)
	if actualProgNum != programNumber {
		log.Printf("parsePMT: WARNING program_number mismatch: got %d, expected %d", actualProgNum, programNumber)
	}

	// Check program info descriptors for CA (scrambling indicator)
	caids := make(map[int]bool)
	for i := 12; i < 12+programInfoLen-1; {
		if i+1 >= len(data) {
			break
		}
		tag := data[i]
		length := int(data[i+1])
		if tag == 0x09 && i+3 < len(data) {
			svc.Scrambled = true
			caid := (int(data[i+2]) << 8) | int(data[i+3])
			if caid != 0 {
				caids[caid] = true
			}
		}
		i += 2 + length
	}

	for offset+5 <= sectionLen-4 {
		streamType := data[offset]
		elemPID := ((int(data[offset+1]) & 0x1F) << 8) | int(data[offset+2])
		esInfoLen := ((int(data[offset+3]) & 0x0F) << 8) | int(data[offset+4])

		switch streamType {
		case 0x01, 0x02, 0x10, 0x1B, 0x24, 0x27: // MPEG-1/2, MPEG-4, H.264, H.265, AV1
			if svc.VideoPID == 0 {
				svc.VideoPID = elemPID
				log.Printf("parsePMT: sid=%d found video streamType=0x%02X pid=%d", programNumber, streamType, elemPID)
			}
		case 0x03, 0x04, 0x0F, 0x11: // MPEG-1/2 Audio, AAC, LATM AAC
			if svc.AudioPID == 0 {
				svc.AudioPID = elemPID
				log.Printf("parsePMT: sid=%d found audio streamType=0x%02X pid=%d", programNumber, streamType, elemPID)
			}
		case 0x06: // PES private data — may be AC3, E-AC3, DTS, teletext, subtitles
			// Peek into ES info descriptors to decide if this is audio.
			isAudio := false
			for d := 0; d+2 < esInfoLen && offset+5+d+2 < len(data); {
				descTag := data[offset+5+d]
				descLen := int(data[offset+5+d+1])
				if offset+5+d+2+descLen > len(data) {
					break
				}
				// AC-3_descriptor = 0x6A, E-AC-3_descriptor = 0x7A, AAC_descriptor = 0x7C
				if descTag == 0x6A || descTag == 0x7A || descTag == 0x7C {
					isAudio = true
				}
				// Subtitling_descriptor = 0x59, teletext_descriptor = 0x56
				if descTag == 0x59 || descTag == 0x56 {
					isAudio = false
					break
				}
				d += 2 + descLen
			}
			if isAudio && svc.AudioPID == 0 {
				svc.AudioPID = elemPID
				log.Printf("parsePMT: sid=%d found private audio streamType=0x%02X pid=%d", programNumber, streamType, elemPID)
			}
		}

		// Parse ISO 639 language descriptor (0x0A) from ES info for any audio track.
		if svc.AudioPID == 0 || svc.AudioPID == elemPID {
			for d := 0; d+4 < esInfoLen && offset+5+d+4 < len(data); {
				descTag := data[offset+5+d]
				descLen := int(data[offset+5+d+1])
				if offset+5+d+2+descLen > len(data) {
					break
				}
				if descTag == 0x0A && descLen >= 3 { // ISO_639_language_descriptor
					lang := string(data[offset+5+d+2 : offset+5+d+5])
					if lang != "" && lang != "\x00\x00\x00" {
						svc.AudioLanguages = append(svc.AudioLanguages, lang)
					}
				}
				d += 2 + descLen
			}
		}

		// Check ES info descriptors for CA
		for i := 0; i < esInfoLen-1 && offset+5+i+1 < len(data); {
			tag := data[offset+5+i]
			dlen := int(data[offset+5+i+1])
			if tag == 0x09 && offset+5+i+3 < len(data) {
				svc.Scrambled = true
				caid := (int(data[offset+5+i+2]) << 8) | int(data[offset+5+i+3])
				if caid != 0 {
					caids[caid] = true
				}
			}
			i += 2 + dlen
		}

		offset += 5 + esInfoLen
	}

	for caid := range caids {
		svc.CAIDs = append(svc.CAIDs, caid)
	}

	log.Printf("parsePMT: sid=%d done video=%d audio=%d pcr=%d scrambled=%v caids=%v", programNumber, svc.VideoPID, svc.AudioPID, svc.PCR_PID, svc.Scrambled, svc.CAIDs)
	return svc
}

// parseSDT extracts service_id -> service_name mappings from an SDT section.
func parseSDT(data []byte) map[int]string {
	if len(data) < 11 {
		return nil
	}
	sectionLen := int(((uint16(data[1])&0x0F)<<8)|uint16(data[2])) + 3
	if sectionLen > len(data) {
		sectionLen = len(data)
	}
	offset := 11 // skip table_id through reserved_future_use

	names := make(map[int]string)
	for offset+5 <= sectionLen-4 {
		serviceID := (int(data[offset]) << 8) | int(data[offset+1])
		descriptorsLen := ((int(data[offset+3]) & 0x0F) << 8) | int(data[offset+4])
		descEnd := offset + 5 + descriptorsLen
		if descEnd > sectionLen-4 {
			descEnd = sectionLen - 4
		}

		for d := offset + 5; d+2 < descEnd; {
			descTag := data[d]
			descLen := int(data[d+1])
			if d+2+descLen > descEnd {
				break
			}
			if descTag == 0x48 && descLen >= 3 { // service_descriptor
				providerLen := int(data[d+3])
				if d+4+providerLen < descEnd {
					nameLen := int(data[d+4+providerLen])
					nameStart := d + 4 + providerLen + 1
					if nameStart+nameLen <= descEnd {
						name := string(data[nameStart : nameStart+nameLen])
						names[serviceID] = sanitizeDVBText(name)
					}
				}
			}
			d += 2 + descLen
		}
		offset += 5 + descriptorsLen
	}
	return names
}

