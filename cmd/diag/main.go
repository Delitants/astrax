//go:build linux

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package main

import (
	"fmt"
	"log"
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

	pilotAuto   = 2
	rolloffAuto = 3

	sysDVBS  = 5
	sysDVBS2 = 6

	dtvTune           = 1
	dtvClear          = 2
	dtvFrequency      = 3
	dtvModulation     = 4
	dtvInversion      = 6
	dtvSymbolRate     = 8
	dtvInnerFEC       = 9
	dtvVoltage        = 10
	dtvTone           = 11
	dtvPilot          = 12
	dtvRolloff        = 13
	dtvDeliverySystem = 17
)

const (
	modQPSK   = 0
	modPSK8   = 9
	modQAMAuto = 6
)

type dtvProperties struct {
	Num   uint32
	Props uintptr
}

type dtvCommand struct {
	cmd  uint32
	data uint32
}

var (
	ioctlSetProperty        = iow(ioctlTypeDVB, 82, unsafe.Sizeof(dtvProperties{}))
	ioctlDiseqcSendMaster   = iow(ioctlTypeDVB, 63, unsafe.Sizeof(diseqcMessage{}))
	ioctlSetTone            = io(ioctlTypeDVB, 66)
	ioctlSetVoltage         = io(ioctlTypeDVB, 67)
	ioctlReadStatus         = ior(ioctlTypeDVB, 69, unsafe.Sizeof(uint32(0)))
	ioctlReadBER            = ior(ioctlTypeDVB, 70, unsafe.Sizeof(uint32(0)))
	ioctlReadSignalStrength = ior(ioctlTypeDVB, 71, unsafe.Sizeof(uint16(0)))
	ioctlReadSNR            = ior(ioctlTypeDVB, 72, unsafe.Sizeof(uint16(0)))
	ioctlReadUncorrected    = ior(ioctlTypeDVB, 73, unsafe.Sizeof(uint32(0)))
)

type diseqcMessage struct {
	Msg [6]byte
	Len uint8
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
	return (dir << iocDirShift) | (typ << iocTypeShift) | (nr << iocNRShift) | (size << iocSizeShift)
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

func dtvPropertySize() int {
	if unsafe.Sizeof(uintptr(0)) == 8 {
		return 76
	}
	return 72
}

func ioctlSetProperties(fd int, commands []dtvCommand) error {
	if len(commands) == 0 {
		return nil
	}
	propSize := dtvPropertySize()
	raw := make([]byte, len(commands)*propSize)
	for i, cmd := range commands {
		offset := i * propSize
		*(*uint32)(unsafe.Pointer(&raw[offset])) = cmd.cmd
		*(*uint32)(unsafe.Pointer(&raw[offset+16])) = cmd.data
	}
	props := dtvProperties{
		Num:   uint32(len(commands)),
		Props: uintptr(unsafe.Pointer(&raw[0])),
	}
	if err := ioctlPtr(fd, ioctlSetProperty, unsafe.Pointer(&props)); err != nil {
		return err
	}
	return nil
}

func tune(fd int, freqKHz uint32, symRate uint32, delivery uint32, voltage uint32, tone uint32, setModulation bool) error {
	commands := []dtvCommand{
		{cmd: dtvClear, data: 0},
		{cmd: dtvDeliverySystem, data: delivery},
		{cmd: dtvFrequency, data: freqKHz},
		{cmd: dtvInversion, data: inversionAuto},
		{cmd: dtvSymbolRate, data: symRate},
		{cmd: dtvInnerFEC, data: fecAuto},
		{cmd: dtvVoltage, data: voltage},
		{cmd: dtvTone, data: tone},
	}
	if delivery == sysDVBS2 {
		commands = append(commands,
			dtvCommand{cmd: dtvPilot, data: pilotAuto},
			dtvCommand{cmd: dtvRolloff, data: rolloffAuto},
		)
	}
	if setModulation {
		commands = append(commands, dtvCommand{cmd: dtvModulation, data: modPSK8})
	}
	commands = append(commands, dtvCommand{cmd: dtvTune, data: 0})
	return ioctlSetProperties(fd, commands)
}

func poll(fd int) (bool, int, int, uint32, uint32, uint32) {
	statusBits, _ := ioctlReadU32(fd, ioctlReadStatus)
	signalRaw, _ := ioctlReadU16(fd, ioctlReadSignalStrength)
	snrRaw, _ := ioctlReadU16(fd, ioctlReadSNR)
	ber, _ := ioctlReadU32(fd, ioctlReadBER)
	unc, _ := ioctlReadU32(fd, ioctlReadUncorrected)

	locked := statusBits&feStatusHasLock != 0
	sigPct := 0
	if signalRaw > 0 {
		sigPct = int((uint32(signalRaw) * 100) / 65535)
	}
	snrPct := 0
	if snrRaw > 0 {
		snrPct = int((uint32(snrRaw) * 100) / 65535)
	}
	return locked, sigPct, snrPct, ber, unc, statusBits
}

func programUnicable(fd int, ifFreqMHz int, slot int, unicableFreq int, unicableType int) error {
	msg := diseqcMessage{}
	fVCOMHz := ifFreqMHz + unicableFreq

	if unicableType == 2 {
		msg.Msg[0] = 0x70
		msg.Len = 3
		tuningWord := int((float64(fVCOMHz) / 2.0) - 100.0 + 0.5)
		if tuningWord < 0 {
			tuningWord = 0
		}
		if tuningWord > 0x7FF {
			tuningWord = 0x7FF
		}
		msg.Msg[1] = byte((slot&0x1F)<<3 | ((tuningWord >> 8) & 0x07))
		msg.Msg[2] = byte(tuningWord & 0xFF)
		fmt.Printf("  EN50607: slot=%d VCO=%dMHz TW=%d msg=[0x%02X 0x%02X 0x%02X]\n",
			slot, fVCOMHz, tuningWord, msg.Msg[0], msg.Msg[1], msg.Msg[2])
	} else {
		msg.Msg[0] = 0xE0
		msg.Msg[1] = 0x10
		msg.Msg[2] = 0x5A
		msg.Len = 5
		tuningWord := int((float64(fVCOMHz) / 4.0) - 350.0 + 0.5)
		if tuningWord < 0 {
			tuningWord = 0
		}
		if tuningWord > 0x3FF {
			tuningWord = 0x3FF
		}
		msg.Msg[3] = byte((slot & 0x07)<<5 | ((tuningWord >> 8) & 0x03))
		msg.Msg[4] = byte(tuningWord & 0xFF)
	}

	if err := ioctlInt(fd, ioctlSetTone, secToneOff); err != nil {
		return fmt.Errorf("disable tone: %w", err)
	}
	cmdVoltage := secVoltage18
	if unicableType == 2 {
		cmdVoltage = secVoltage13
	}
	if err := ioctlInt(fd, ioctlSetVoltage, uintptr(cmdVoltage)); err != nil {
		return fmt.Errorf("set voltage: %w", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := ioctlPtr(fd, ioctlDiseqcSendMaster, unsafe.Pointer(&msg)); err != nil {
		return fmt.Errorf("diseqc: %w", err)
	}
	fmt.Println("  DiSEqC sent (attempt 1)")
	time.Sleep(50 * time.Millisecond)
	if err := ioctlPtr(fd, ioctlDiseqcSendMaster, unsafe.Pointer(&msg)); err != nil {
		return fmt.Errorf("diseqc repeat: %w", err)
	}
	fmt.Println("  DiSEqC sent (attempt 2)")
	time.Sleep(50 * time.Millisecond)
	return nil
}

func main() {
	path := "/dev/dvb/adapter19/frontend0"
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer syscall.Close(fd)

	freqKHz := uint32(1471000)
	symRate := uint32(30000000)
	delivery := uint32(sysDVBS2)
	voltage := uint32(secVoltage13)
	tone := uint32(secToneOff)

	fmt.Printf("Testing: freq=%d kHz, sr=%d, delivery=DVB-S2, voltage=13V, tone=off\n", freqKHz, symRate)

	// Test 1: Without modulation
	fmt.Println("\n--- Test 1: Without DTV_MODULATION ---")
	if err := tune(fd, freqKHz, symRate, delivery, voltage, tone, false); err != nil {
		log.Printf("tune error: %v", err)
	}
	for i := 0; i < 10; i++ {
		locked, sig, snr, ber, unc, status := poll(fd)
		fmt.Printf("[%02d] locked=%v signal=%d%% snr=%d%% ber=%d unc=%d status=0x%02x\n", i, locked, sig, snr, ber, unc, status)
		time.Sleep(1 * time.Second)
	}

	// Test 2: With 8PSK modulation
	fmt.Println("\n--- Test 2: With DTV_MODULATION=PSK_8 ---")
	if err := tune(fd, freqKHz, symRate, delivery, voltage, tone, true); err != nil {
		log.Printf("tune error: %v", err)
	}
	for i := 0; i < 10; i++ {
		locked, sig, snr, ber, unc, status := poll(fd)
		fmt.Printf("[%02d] locked=%v signal=%d%% snr=%d%% ber=%d unc=%d status=0x%02x\n", i, locked, sig, snr, ber, unc, status)
		time.Sleep(1 * time.Second)
	}

	// Test 3: With unicable DiSEqC + 8PSK
	fmt.Println("\n--- Test 3: With EN50607 DiSEqC + PSK_8 ---")
	if err := programUnicable(fd, 1555, 15, 1470, 2); err != nil {
		log.Printf("unicable error: %v", err)
	}
	if err := tune(fd, freqKHz, symRate, delivery, voltage, tone, true); err != nil {
		log.Printf("tune error: %v", err)
	}
	for i := 0; i < 15; i++ {
		locked, sig, snr, ber, unc, status := poll(fd)
		fmt.Printf("[%02d] locked=%v signal=%d%% snr=%d%% ber=%d unc=%d status=0x%02x\n", i, locked, sig, snr, ber, unc, status)
		if locked {
			fmt.Println("LOCKED!")
		}
		time.Sleep(1 * time.Second)
	}
}
