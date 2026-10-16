//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package dvb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
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

	iocNone  = 0
	iocWrite = 1
	iocRead  = 2
)

const (
	feStatusHasLock = 0x10

	secToneOn  = 0
	secToneOff = 1

	secVoltage13 = 0
	secVoltage18 = 1

	inversionAuto = 2
	fecAuto       = 9
	fec12         = 1
	fec23         = 2
	fec34         = 3
	fec45         = 4
	fec56         = 5
	fec67         = 6
	fec78         = 7
	fec89         = 8
	fec35         = 10
	fec910        = 11

	pilotOn   = 0
	pilotOff  = 1
	pilotAuto = 2

	rolloff35   = 0
	rolloff20   = 1
	rolloff25   = 2
	rolloffAuto = 3

	sysDVBS  = 5
	sysDVBS2 = 6

	dtvTune           = 1
	dtvClear          = 2
	dtvFrequency      = 3
	dtvInversion      = 6
	dtvSymbolRate     = 8
	dtvInnerFEC       = 9
	dtvVoltage        = 10
	dtvTone           = 11
	dtvPilot          = 12
	dtvRolloff        = 13
	dtvModulation     = 4
	dtvDeliverySystem = 17
	dtvStreamID       = 42
	noStreamIDFilter  = ^uint32(0)

	modQPSK   = 0
	modAuto   = 6
	mod8PSK   = 9
	mod16APSK = 10
	mod32APSK = 11
)

type linuxSession struct {
	fd  int
	cfg Config
}

type dtvProperties struct {
	Num   uint32
	Props uintptr
}

type diseqcMessage struct {
	Msg [6]byte
	Len uint8
}

type dtvCommand struct {
	cmd  uint32
	data uint32
}

type dvbFrontendParameters struct {
	Frequency  uint32
	Inversion  uint32
	SymbolRate uint32
	FECInner   uint32
}

var (
	ioctlSetProperty        = iow(ioctlTypeDVB, 82, unsafe.Sizeof(dtvProperties{}))
	ioctlSetFrontendV3      = iow(ioctlTypeDVB, 76, unsafe.Sizeof(dvbFrontendParameters{}))
	ioctlDiseqcSendMaster   = iow(ioctlTypeDVB, 63, unsafe.Sizeof(diseqcMessage{}))
	ioctlSetTone            = io(ioctlTypeDVB, 66)
	ioctlSetVoltage         = io(ioctlTypeDVB, 67)
	ioctlReadStatus         = ior(ioctlTypeDVB, 69, unsafe.Sizeof(uint32(0)))
	ioctlReadBER            = ior(ioctlTypeDVB, 70, unsafe.Sizeof(uint32(0)))
	ioctlReadSignalStrength = ior(ioctlTypeDVB, 71, unsafe.Sizeof(uint16(0)))
	ioctlReadSNR            = ior(ioctlTypeDVB, 72, unsafe.Sizeof(uint16(0)))
	ioctlReadUncorrected    = ior(ioctlTypeDVB, 73, unsafe.Sizeof(uint32(0)))

	dmxSetPESFilter  = iow(ioctlTypeDVB, 44, unsafe.Sizeof(dmxPesFilterParams{}))
	dmxStart         = io(ioctlTypeDVB, 41)
	dmxStop          = io(ioctlTypeDVB, 42)
	dmxSetBufferSize = io(ioctlTypeDVB, 45)
	dmxAddPID        = iow(ioctlTypeDVB, 51, unsafe.Sizeof(uint16(0)))

	dmxInFrontend    uint32 = 0
	dmxOutTSTap      uint32 = 2
	dmxOutTSDemuxTap uint32 = 3
	dmxPESVideo0     uint32 = 0
	dmxPESAudio0     uint32 = 1
	dmxPESTeletext0  uint32 = 2
	dmxPESSubtitle0  uint32 = 3
	dmxPESPCR0       uint32 = 4
	dmxPESOther      uint32 = 0x14
)

func OpenSession(cfg Config) (Session, error) {
	path := filepath.Join("/dev/dvb", fmt.Sprintf("adapter%d", cfg.Adapter), fmt.Sprintf("frontend%d", cfg.Frontend))
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("dvb frontend not found at %s", path)
		}
		return nil, fmt.Errorf("open dvb frontend: %w", err)
	}

	s := &linuxSession{fd: fd, cfg: cfg}
	if err := s.tune(); err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	return s, nil
}

func (s *linuxSession) clearFrontend() error {
	if err := ioctlSetProperties(s.fd, []dtvCommand{{cmd: dtvClear, data: 0}}); err != nil {
		return fmt.Errorf("clear frontend: %w", err)
	}
	return nil
}

func (s *linuxSession) Close() error {
	if s.fd < 0 {
		return nil
	}
	err := syscall.Close(s.fd)
	s.fd = -1
	if err != nil {
		return fmt.Errorf("close dvb frontend: %w", err)
	}
	return nil
}

func (s *linuxSession) DemuxPath() string {
	return filepath.Join("/dev/dvb", fmt.Sprintf("adapter%d", s.cfg.Adapter), fmt.Sprintf("demux%d", s.cfg.Frontend))
}

func (s *linuxSession) Poll() (Signal, error) {
	statusBits, err := ioctlReadU32(s.fd, ioctlReadStatus)
	if err != nil {
		return Signal{}, fmt.Errorf("read frontend status: %w", err)
	}

	locked := statusBits&feStatusHasLock != 0
	sig := Signal{
		Locked:     locked,
		StatusBits: statusBits,
	}

	if !locked {
		// Log status bits on every poll to help debug tuning issues.
		log.Printf("poll: adapter%d.frontend%d no lock, status=0x%04X", s.cfg.Adapter, s.cfg.Frontend, statusBits)
		return sig, nil
	}

	signalRaw, _ := ioctlReadU16(s.fd, ioctlReadSignalStrength)
	snrRaw, _ := ioctlReadU16(s.fd, ioctlReadSNR)
	ber, _ := ioctlReadU32(s.fd, ioctlReadBER)
	unc, _ := ioctlReadU32(s.fd, ioctlReadUncorrected)

	sig.SignalPercent = scaleU16(signalRaw)
	sig.SNRPercent = scaleU16(snrRaw)
	sig.BER = ber
	sig.UncorrectedBlocks = unc
	return sig, nil
}

func (s *linuxSession) tune() error {
	cfg := s.cfg

	ifFreqKHz := IntermediateFrequencyKHz(cfg)
	if ifFreqKHz == 0 {
		return fmt.Errorf("invalid IF frequency")
	}

	highBand := IsHighBand(cfg)
	horizontal := IsHorizontal(cfg)
	tuneFreqKHz := ifFreqKHz

	log.Printf("tune: adapter%d.frontend%d start freq=%d kHz pol=%s delivery=%s", cfg.Adapter, cfg.Frontend, ifFreqKHz, cfg.Polarization, cfg.Delivery)

	// Clear frontend state before any voltage/tone changes.
	// This resets the driver's internal property cache without
	// affecting the physical LNB (voltage/tone are separate ioctls).
	log.Printf("tune: adapter%d.frontend%d clearing frontend...", cfg.Adapter, cfg.Frontend)
	if err := s.clearFrontend(); err != nil {
		return err
	}
	log.Printf("tune: adapter%d.frontend%d frontend cleared OK", cfg.Adapter, cfg.Frontend)

	if cfg.UnicableType > 0 {
		ifFreqMHz := int((ifFreqKHz + 500) / 1000)
		tuneMHz, err := s.programUnicable(ifFreqMHz, highBand, horizontal)
		if err != nil {
			return err
		}
		if tuneMHz <= 0 {
			return fmt.Errorf("unicable generated invalid tune frequency %d MHz", tuneMHz)
		}
		tuneFreqKHz = uint32(tuneMHz * 1000)
		log.Printf("tune: adapter%d.frontend%d unicable tuneFreq=%d kHz", cfg.Adapter, cfg.Frontend, tuneFreqKHz)
	} else {
		log.Printf("tune: adapter%d.frontend%d configuring legacy LNB highBand=%v horizontal=%v", cfg.Adapter, cfg.Frontend, highBand, horizontal)
		if err := s.configureLegacyLNB(highBand, horizontal); err != nil {
			return err
		}
		log.Printf("tune: adapter%d.frontend%d legacy LNB configured OK", cfg.Adapter, cfg.Frontend)
	}

	commands, err := buildV5TuneCommands(cfg, tuneFreqKHz)
	if err != nil {
		return err
	}
	if useLegacyDVBAPIV3(cfg) {
		return s.tuneV3(tuneFreqKHz, cfg.SymbolRate)
	}

	log.Printf("tune: adapter%d.frontend%d sending %d DTV properties (delivery=%s freq=%d symrate=%d)", cfg.Adapter, cfg.Frontend, len(commands), cfg.Delivery, tuneFreqKHz, cfg.SymbolRate)
	if err := ioctlSetProperties(s.fd, commands); err != nil {
		return fmt.Errorf("tune dvb frontend: %w", err)
	}
	log.Printf("tune: adapter%d.frontend%d ioctl OK, waiting for lock...", cfg.Adapter, cfg.Frontend)
	return nil
}

func useLegacyDVBAPIV3(cfg Config) bool {
	dvbAPI := cfg.DVBAPI
	if dvbAPI == "" && cfg.DVBAPIV3 {
		dvbAPI = "v3"
	}
	return dvbAPI == "v3" && cfg.Delivery == "dvbs"
}

func buildV5TuneCommands(cfg Config, tuneFreqKHz uint32) ([]dtvCommand, error) {
	delivery := uint32(sysDVBS)
	if cfg.Delivery == "dvbs2" {
		delivery = uint32(sysDVBS2)
	} else if cfg.StreamID != "" {
		return nil, fmt.Errorf("stream_id is only supported for DVB-S2")
	}

	voltage := uint32(secVoltage13)
	if IsHorizontal(cfg) {
		voltage = uint32(secVoltage18)
	}
	tone := uint32(secToneOff)
	if cfg.UnicableType == 0 && (IsHighBand(cfg) || cfg.ForceTone) {
		tone = uint32(secToneOn)
	}

	// Keep DTV_CLEAR and DTV_TUNE in the same atomic property list.
	commands := []dtvCommand{
		{cmd: dtvClear, data: 0},
		{cmd: dtvDeliverySystem, data: delivery},
		{cmd: dtvFrequency, data: tuneFreqKHz},
		{cmd: dtvInversion, data: inversionAuto},
		{cmd: dtvSymbolRate, data: cfg.SymbolRate},
		{cmd: dtvInnerFEC, data: fecValue(cfg.FEC)},
	}
	if cfg.UnicableType == 0 {
		commands = append(commands,
			dtvCommand{cmd: dtvVoltage, data: voltage},
			dtvCommand{cmd: dtvTone, data: tone},
		)
	}
	if cfg.Delivery == "dvbs2" {
		streamID, err := linuxStreamID(cfg.StreamID)
		if err != nil {
			return nil, err
		}
		commands = append(commands,
			dtvCommand{cmd: dtvModulation, data: modulationValue(cfg.Modulation)},
			dtvCommand{cmd: dtvPilot, data: pilotAuto},
			dtvCommand{cmd: dtvRolloff, data: rolloffValue(cfg.RollOff)},
			dtvCommand{cmd: dtvStreamID, data: streamID},
		)
	}
	return append(commands, dtvCommand{cmd: dtvTune, data: 0}), nil
}

func linuxStreamID(value string) (uint32, error) {
	if value == "" {
		return noStreamIDFilter, nil
	}
	if !decimalDigits(value) {
		return 0, fmt.Errorf("stream_id %q is not a canonical decimal DVB-S2 ISI", value)
	}
	streamID, err := strconv.ParseUint(value, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("stream_id %q must be between 0 and 255", value)
	}
	if strconv.FormatUint(streamID, 10) != value {
		return 0, fmt.Errorf("stream_id %q is not a canonical decimal DVB-S2 ISI", value)
	}
	return uint32(streamID), nil
}

func (s *linuxSession) tuneV3(freqKHz, symbolRate uint32) error {
	params := dvbFrontendParameters{
		Frequency:  freqKHz,
		Inversion:  uint32(inversionAuto),
		SymbolRate: symbolRate,
		FECInner:   uint32(fecAuto),
	}
	if err := ioctlPtr(s.fd, ioctlSetFrontendV3, unsafe.Pointer(&params)); err != nil {
		return fmt.Errorf("tune dvb frontend v3: %w", err)
	}
	return nil
}

func (s *linuxSession) configureLegacyLNB(highBand, horizontal bool) error {
	log.Printf("tune: adapter%d.frontend%d legacy LNB tone OFF", s.cfg.Adapter, s.cfg.Frontend)
	if err := s.setTone(secToneOff); err != nil {
		return fmt.Errorf("disable tone before diseqc: %w", err)
	}

	log.Printf("tune: adapter%d.frontend%d setting voltage for pol=%v", s.cfg.Adapter, s.cfg.Frontend, horizontal)
	if err := s.setVoltageForPolarization(horizontal); err != nil {
		return fmt.Errorf("set lnb voltage: %w", err)
	}

	if err := sleepContext(15 * time.Millisecond); err != nil {
		return err
	}

	log.Printf("tune: adapter%d.frontend%d sending committed diseqc port=%d highBand=%v horizontal=%v", s.cfg.Adapter, s.cfg.Frontend, s.cfg.DiseqcPort, highBand, horizontal)
	if err := s.sendCommittedDiseqc(highBand, horizontal); err != nil {
		return err
	}

	if err := sleepContext(15 * time.Millisecond); err != nil {
		return err
	}

	forceTone := s.cfg.ForceTone
	if forceTone || highBand {
		log.Printf("tune: adapter%d.frontend%d setting tone ON (forceTone=%v highBand=%v)", s.cfg.Adapter, s.cfg.Frontend, forceTone, highBand)
		if err := s.setTone(secToneOn); err != nil {
			return fmt.Errorf("set tone on: %w", err)
		}
	} else {
		log.Printf("tune: adapter%d.frontend%d setting tone OFF", s.cfg.Adapter, s.cfg.Frontend)
		if err := s.setTone(secToneOff); err != nil {
			return fmt.Errorf("set tone off: %w", err)
		}
	}

	return nil
}

func (s *linuxSession) sendCommittedDiseqc(highBand, horizontal bool) error {
	port := s.cfg.DiseqcPort
	if port < 0 {
		port = 0
	}

	data := byte(0xF0 | ((port & 0x03) << 2))
	if horizontal {
		data |= 0x02
	}
	if highBand {
		data |= 0x01
	}

	msg := diseqcMessage{}
	msg.Msg[0] = 0xE0
	msg.Msg[1] = 0x10
	msg.Msg[2] = 0x38
	msg.Msg[3] = data
	msg.Len = 4

	if err := ioctlPtr(s.fd, ioctlDiseqcSendMaster, unsafe.Pointer(&msg)); err != nil {
		return fmt.Errorf("send diseqc command failed: %w", err)
	}
	return nil
}

func (s *linuxSession) programUnicable(ifFreqMHz int, highBand, horizontal bool) (int, error) {
	msg := diseqcMessage{}
	offsetMHz := 0
	position := s.cfg.DiseqcPort
	if position < 0 {
		position = 0
	}

	switch s.cfg.UnicableType {
	case 1:
		msg.Msg[0] = 0xE0
		msg.Msg[1] = 0x10
		msg.Msg[2] = 0x5A
		msg.Len = 5

		if s.cfg.UnicablePIN >= 0 {
			msg.Msg[2] = 0x5C
			msg.Len = 6
			msg.Msg[5] = byte(s.cfg.UnicablePIN)
		}

		// EN50494 slot index is 0-based; UI uses 1-based numbering.
		slotIdx := s.cfg.UnicableSlot
		if slotIdx > 0 {
			slotIdx--
		}

		fVCOMHz := ifFreqMHz + s.cfg.UnicableFreq
		tuningWord := int((float64(fVCOMHz) / 4.0) - 350.0 + 0.5)
		if tuningWord < 0 {
			tuningWord = 0
		}
		if tuningWord > 0x3FF {
			tuningWord = 0x3FF
		}

		b3 := byte((slotIdx & 0x07) << 5)
		if highBand {
			b3 |= 1 << 2
		}
		if horizontal {
			b3 |= 1 << 3
		}
		if position&0x01 == 1 {
			b3 |= 1 << 4
		}
		b3 |= byte((tuningWord >> 8) & 0x03)
		msg.Msg[3] = b3
		msg.Msg[4] = byte(tuningWord & 0xFF)

		log.Printf("tune: adapter%d.frontend%d unicable I slot=%d slotIdx=%d tw=%d", s.cfg.Adapter, s.cfg.Frontend, s.cfg.UnicableSlot, slotIdx, tuningWord)

		offsetMHz = ((tuningWord + 350) * 4) - fVCOMHz
	case 2:
		// EN50607 slot index is 0-based; UI uses 1-based numbering.
		slotIdx := s.cfg.UnicableSlot
		if slotIdx > 0 {
			slotIdx--
		}

		msg.Msg[0] = 0x70
		msg.Len = 4

		tuningWord := ifFreqMHz - 100
		if tuningWord < 0 {
			tuningWord = 0
		}
		if tuningWord > 0x7FF {
			tuningWord = 0x7FF
		}

		data3 := byte((position & 0x3F) << 2)
		if horizontal {
			data3 |= 1 << 1
		}
		if highBand {
			data3 |= 1
		}

		msg.Msg[1] = byte((slotIdx&0x1F)<<3 | ((tuningWord >> 8) & 0x07))
		msg.Msg[2] = byte(tuningWord & 0xFF)
		msg.Msg[3] = data3

		log.Printf("tune: adapter%d.frontend%d unicable II slot=%d slotIdx=%d tw=%d", s.cfg.Adapter, s.cfg.Frontend, s.cfg.UnicableSlot, slotIdx, tuningWord)

		if s.cfg.UnicablePIN >= 0 {
			msg.Msg[0] = 0x71
			msg.Len = 5
			msg.Msg[4] = byte(s.cfg.UnicablePIN)
		}

		offsetMHz = (tuningWord + 100) - ifFreqMHz
	default:
		return 0, fmt.Errorf("unknown unicable type %d", s.cfg.UnicableType)
	}

	if s.cfg.UnicableType == 2 {
		log.Printf("tune: adapter%d.frontend%d unicable II sequence start", s.cfg.Adapter, s.cfg.Frontend)
		// EN50607 (Unicable II / JESS) sequence matching Astra Cesbo:
		// 13V -> tone ON -> 18V -> single DiSEqC command -> restore polarization voltage
		if err := s.setVoltage(secVoltage13); err != nil {
			return 0, fmt.Errorf("unicable: set 13V failed: %w", err)
		}
		if err := s.setTone(secToneOn); err != nil {
			return 0, fmt.Errorf("unicable: set tone on failed: %w", err)
		}
		if err := s.setVoltage(secVoltage18); err != nil {
			return 0, fmt.Errorf("unicable: set 18V failed: %w", err)
		}
		log.Printf("tune: adapter%d.frontend%d unicable II sending diseqc", s.cfg.Adapter, s.cfg.Frontend)
		if err := ioctlPtr(s.fd, ioctlDiseqcSendMaster, unsafe.Pointer(&msg)); err != nil {
			return 0, fmt.Errorf("unicable: diseqc command failed: %w", err)
		}
		if err := sleepContext(50 * time.Millisecond); err != nil {
			return 0, err
		}
		if err := s.setVoltageForPolarization(horizontal); err != nil {
			return 0, fmt.Errorf("unicable: restore voltage failed: %w", err)
		}
		log.Printf("tune: adapter%d.frontend%d unicable II sequence done", s.cfg.Adapter, s.cfg.Frontend)
	} else {
		log.Printf("tune: adapter%d.frontend%d unicable I sequence start", s.cfg.Adapter, s.cfg.Frontend)
		// EN50494 (Unicable I) sequence
		if err := s.setTone(secToneOff); err != nil {
			return 0, fmt.Errorf("unicable: disable tone failed: %w", err)
		}
		if err := s.setVoltage(secVoltage18); err != nil {
			return 0, fmt.Errorf("unicable: set command voltage failed: %w", err)
		}
		if err := sleepContext(100 * time.Millisecond); err != nil {
			return 0, err
		}
		if err := ioctlPtr(s.fd, ioctlDiseqcSendMaster, unsafe.Pointer(&msg)); err != nil {
			return 0, fmt.Errorf("unicable: diseqc command failed: %w", err)
		}
		if err := sleepContext(50 * time.Millisecond); err != nil {
			return 0, err
		}
		if err := ioctlPtr(s.fd, ioctlDiseqcSendMaster, unsafe.Pointer(&msg)); err != nil {
			return 0, fmt.Errorf("unicable: diseqc repeat command failed: %w", err)
		}
		if err := sleepContext(50 * time.Millisecond); err != nil {
			return 0, err
		}
		if err := s.setVoltageForPolarization(horizontal); err != nil {
			return 0, fmt.Errorf("unicable: restore voltage failed: %w", err)
		}
		if err := sleepContext(50 * time.Millisecond); err != nil {
			return 0, err
		}
		log.Printf("tune: adapter%d.frontend%d unicable I sequence done", s.cfg.Adapter, s.cfg.Frontend)
	}

	return s.cfg.UnicableFreq + offsetMHz, nil
}

func (s *linuxSession) setVoltageForPolarization(horizontal bool) error {
	if horizontal {
		return s.setVoltage(secVoltage18)
	}
	return s.setVoltage(secVoltage13)
}

func (s *linuxSession) setVoltage(voltage uint32) error {
	if err := ioctlInt(s.fd, ioctlSetVoltage, uintptr(voltage)); err != nil {
		return err
	}
	return nil
}

func (s *linuxSession) setTone(tone uint32) error {
	if err := ioctlInt(s.fd, ioctlSetTone, uintptr(tone)); err != nil {
		return err
	}
	return nil
}

func ioctlSetProperties(fd int, commands []dtvCommand) error {
	if len(commands) == 0 {
		return nil
	}

	propSize := dtvPropertySize()
	raw := make([]byte, len(commands)*propSize)

	for i, cmd := range commands {
		offset := i * propSize
		binary.LittleEndian.PutUint32(raw[offset:], cmd.cmd)
		// dtv_property: cmd=4, reserved[3]=12, u.data at offset 16
		binary.LittleEndian.PutUint32(raw[offset+16:], cmd.data)
	}

	props := dtvProperties{
		Num:   uint32(len(commands)),
		Props: uintptr(unsafe.Pointer(&raw[0])),
	}

	if err := ioctlPtr(fd, ioctlSetProperty, unsafe.Pointer(&props)); err != nil {
		return err
	}

	runtime.KeepAlive(raw)
	return nil
}

// dtvPropertySize returns the kernel struct dtv_property size.
// The header on this system shows reserved[3] (12 bytes), so the
// struct is cmd(4) + reserved(12) + u.data(8) + result(8) = 32
// on both 32-bit and 64-bit.  However Go's unsafe.Sizeof(uint64)=8
// regardless of arch, so the union is 8 bytes.  With 4-byte alignment
// the struct ends at 32 bytes.  But empirically on 64-bit Linux 6.8
// the struct size is 76 bytes (4 + 12 + 56 + 4 padding).  The critical
// offset of u.data is +16 from the start of cmd.
func dtvPropertySize() int {
	return 76
}

func ioctlPtr(fd int, req uintptr, ptr unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(ptr))
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlInt(fd int, req uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func ioctlReadU16(fd int, req uintptr) (uint16, error) {
	var v uint16
	if err := ioctlPtr(fd, req, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

func ioctlReadU32(fd int, req uintptr) (uint32, error) {
	var v uint32
	if err := ioctlPtr(fd, req, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

type dmxPesFilterParams struct {
	PID     uint16
	Input   uint32
	Output  uint32
	PESType uint32
	Flags   uint32
}

type linuxDemuxReader struct {
	dvrFd      int
	demuxFds   []int
	errCounter int
}

// pidFilterReader wraps a DemuxReader and drops TS packets whose PID is
// not in the allowed set. Used when the driver only supports a single
// demux filter and we must fall back to the full-TS tap (PID 0x2000).
type pidFilterReader struct {
	inner      DemuxReader
	allowed    map[uint16]bool
	readCnt    int
	dropCnt    int
	loggedPIDs map[uint16]bool
}

func newPIDFilterReader(inner DemuxReader, pids []int) *pidFilterReader {
	allowed := make(map[uint16]bool, len(pids))
	for _, pid := range pids {
		allowed[uint16(pid)] = true
	}
	log.Printf("pidFilterReader: created with allowed PIDs %v", pids)
	return &pidFilterReader{inner: inner, allowed: allowed, loggedPIDs: make(map[uint16]bool)}
}

func (r *pidFilterReader) ReadPacket() ([]byte, error) {
	for {
		pkt, err := r.inner.ReadPacket()
		if err != nil {
			return nil, err
		}
		r.readCnt++
		if len(pkt) < 3 {
			continue
		}
		pid := uint16(pkt[1]&0x1F)<<8 | uint16(pkt[2])
		if r.allowed[pid] {
			return pkt, nil
		}
		r.dropCnt++
	}
}

func (r *pidFilterReader) Close() error {
	return r.inner.Close()
}

func (s *linuxSession) OpenDemux(videoPID, audioPID, pcrPID int) (DemuxReader, error) {
	adapter := s.cfg.Adapter
	frontend := s.cfg.Frontend

	demuxPath := filepath.Join("/dev/dvb", fmt.Sprintf("adapter%d", adapter), fmt.Sprintf("demux%d", frontend))
	dvrPath := filepath.Join("/dev/dvb", fmt.Sprintf("adapter%d", adapter), fmt.Sprintf("dvr%d", frontend))

	pids := demuxServicePIDs(pcrPID, videoPID, audioPID)

	// If no service PIDs are configured, try full-TS tap (PID 0x2000).
	if len(pids) == 0 {
		log.Printf("OpenDemux: no PIDs configured, using full-TS tap 0x2000 on adapter%d.frontend%d", adapter, frontend)
		return s.openDemuxPID(demuxPath, dvrPath, 0x2000)
	}

	log.Printf("OpenDemux: adapter%d.frontend%d trying full-TS tap 0x2000 with software PID filter %v", adapter, frontend, pids)
	reader, fullErr := s.openDemuxPID(demuxPath, dvrPath, 0x2000)
	if fullErr == nil {
		log.Printf("OpenDemux: adapter%d.frontend%d using full-TS tap + pidFilterReader %v", adapter, frontend, pids)
		return newPIDFilterReader(reader, pids), nil
	}

	log.Printf("OpenDemux: adapter%d.frontend%d full-TS tap failed (%v), falling back to video-only PID %d", adapter, frontend, fullErr, videoPID)
	reader, vidErr := s.openDemuxPID(demuxPath, dvrPath, videoPID)
	if vidErr == nil {
		return reader, nil
	}

	return nil, fmt.Errorf("no demux mode available: full-ts=%v, video-only=%v", fullErr, vidErr)
}

func demuxServicePIDs(pcrPID, videoPID, audioPID int) []int {
	pids := make([]int, 0, 3)
	seen := make(map[int]struct{}, 3)
	for _, pid := range []int{pcrPID, videoPID, audioPID} {
		if pid <= 0 || pid > 0x1fff {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		pids = append(pids, pid)
	}
	return pids
}

// openDemuxPIDs opens one demux fd per PID and sets a PES filter on each.
// On failure it closes everything it opened and returns an error.
func (s *linuxSession) openDemuxPIDs(demuxPath string, dvrFd int, pids []int) ([]int, error) {
	demuxFds := make([]int, 0, len(pids))
	cleanup := func() {
		for _, fd := range demuxFds {
			_ = ioctlInt(fd, dmxStop, 0)
			_ = syscall.Close(fd)
		}
	}

	for _, pid := range pids {
		fd, err := syscall.Open(demuxPath, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("open demux %s: %w", demuxPath, err)
		}

		if err := ioctlInt(fd, dmxSetBufferSize, 1024*1024); err != nil {
			_ = ioctlInt(fd, dmxStop, 0)
			_ = syscall.Close(fd)
			cleanup()
			return nil, fmt.Errorf("set demux buffer: %w", err)
		}

		if err := s.setPESFilter(fd, uint16(pid)); err != nil {
			_ = ioctlInt(fd, dmxStop, 0)
			_ = syscall.Close(fd)
			cleanup()
			return nil, fmt.Errorf("set pes filter pid=%d: %w", pid, err)
		}

		if err := ioctlInt(fd, dmxStart, 0); err != nil {
			_ = ioctlInt(fd, dmxStop, 0)
			_ = syscall.Close(fd)
			cleanup()
			return nil, fmt.Errorf("start demux pid=%d: %w", pid, err)
		}

		demuxFds = append(demuxFds, fd)
	}
	return demuxFds, nil
}

// setPESFilter sets the PES filter using the same PES type as the original
// working code (DMX_PES_VIDEO0).  Some drivers accept DMX_PES_OTHER but then
// never output data with it, so we always use DMX_PES_VIDEO0 first and only
// fall back to DMX_PES_OTHER if the ioctl is rejected.
func (s *linuxSession) setPESFilter(fd int, pid uint16) error {
	filter := dmxPesFilterParams{
		PID:     pid,
		Input:   dmxInFrontend,
		Output:  dmxOutTSTap,
		PESType: dmxPESVideo0,
		Flags:   0,
	}
	if err := ioctlPtr(fd, dmxSetPESFilter, unsafe.Pointer(&filter)); err != nil {
		filter.PESType = dmxPESOther
		if err := ioctlPtr(fd, dmxSetPESFilter, unsafe.Pointer(&filter)); err != nil {
			return err
		}
	}
	return nil
}

// openDemuxPID opens the demux for a single PID (used for full-TS tap).
func (s *linuxSession) openDemuxPID(demuxPath, dvrPath string, pid int) (DemuxReader, error) {
	dvrFd, err := syscall.Open(dvrPath, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open dvr %s: %w", dvrPath, err)
	}

	fd, err := syscall.Open(demuxPath, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = syscall.Close(dvrFd)
		return nil, fmt.Errorf("open demux %s: %w", demuxPath, err)
	}

	if err := ioctlInt(fd, dmxSetBufferSize, 1024*1024); err != nil {
		_ = syscall.Close(fd)
		_ = syscall.Close(dvrFd)
		return nil, fmt.Errorf("set demux buffer: %w", err)
	}

	if err := s.setPESFilter(fd, uint16(pid)); err != nil {
		_ = syscall.Close(fd)
		_ = syscall.Close(dvrFd)
		return nil, fmt.Errorf("set pes filter pid=%d: %w", pid, err)
	}

	if err := ioctlInt(fd, dmxStart, 0); err != nil {
		_ = syscall.Close(fd)
		_ = syscall.Close(dvrFd)
		return nil, fmt.Errorf("start demux pid=%d: %w", pid, err)
	}

	time.Sleep(200 * time.Millisecond)
	return &linuxDemuxReader{dvrFd: dvrFd, demuxFds: []int{fd}}, nil
}

func (r *linuxDemuxReader) ReadPacket() ([]byte, error) {
	buf := make([]byte, 188)
	n, err := syscall.Read(r.dvrFd, buf)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, syscall.EAGAIN
	}
	if n < 188 {
		return buf[:n], nil
	}
	return buf, nil
}

func (r *linuxDemuxReader) Close() error {
	var firstErr error
	// Close DVR fd BEFORE demux fd. Some drivers get stuck on reopen
	// if the demux is torn down while the DVR fd is still open.
	if r.dvrFd >= 0 {
		if err := syscall.Close(r.dvrFd); err != nil && firstErr == nil {
			firstErr = err
		}
		r.dvrFd = -1
	}
	for _, fd := range r.demuxFds {
		if fd >= 0 {
			// Explicit dmxStop before close; some drivers require this
			// to fully detach the filter and allow clean reopen.
			_ = ioctlInt(fd, dmxStop, 0)
			if err := syscall.Close(fd); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	r.demuxFds = nil
	return firstErr
}

func scaleU16(raw uint16) int {
	if raw == 0 {
		return 0
	}
	return int((uint32(raw) * 100) / 65535)
}

func io(typ, nr uintptr) uintptr {
	return ioc(iocNone, typ, nr, 0)
}

func ior(typ, nr, size uintptr) uintptr {
	return ioc(iocRead, typ, nr, size)
}

func iow(typ, nr, size uintptr) uintptr {
	return ioc(iocWrite, typ, nr, size)
}

func ioc(dir, typ, nr, size uintptr) uintptr {
	return (dir << iocDirShift) |
		(typ << iocTypeShift) |
		(nr << iocNRShift) |
		(size << iocSizeShift)
}

func sleepContext(d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	<-t.C
	return nil
}

func modulationValue(mod string) uint32 {
	switch strings.ToLower(strings.TrimSpace(mod)) {
	case "auto":
		return uint32(modAuto)
	case "8psk", "psk_8":
		return uint32(mod8PSK)
	case "16apsk", "apsk_16":
		return uint32(mod16APSK)
	case "32apsk", "apsk_32":
		return uint32(mod32APSK)
	case "qpsk", "psk":
		return uint32(modQPSK)
	default:
		return uint32(modAuto)
	}
}

func fecValue(fec string) uint32 {
	switch strings.ToLower(strings.TrimSpace(fec)) {
	case "12", "1/2":
		return uint32(fec12)
	case "23", "2/3":
		return uint32(fec23)
	case "34", "3/4":
		return uint32(fec34)
	case "45", "4/5":
		return uint32(fec45)
	case "56", "5/6":
		return uint32(fec56)
	case "67", "6/7":
		return uint32(fec67)
	case "78", "7/8":
		return uint32(fec78)
	case "89", "8/9":
		return uint32(fec89)
	case "35", "3/5":
		return uint32(fec35)
	case "910", "9/10":
		return uint32(fec910)
	default:
		return uint32(fecAuto)
	}
}

func rolloffValue(ro string) uint32 {
	switch strings.ToLower(strings.TrimSpace(ro)) {
	case "20", "0.20":
		return uint32(rolloff20)
	case "25", "0.25":
		return uint32(rolloff25)
	case "35", "0.35":
		return uint32(rolloff35)
	default:
		return uint32(rolloffAuto)
	}
}
