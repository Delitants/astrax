// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"sync"
	"time"
)

const (
	ecmWireTransactions      = 1
	ecmProfileOperations     = 128
	ecmServiceOperations     = 2
	ecmServiceBindings       = 64
	ecmOperationWaiters      = 16
	ecmProcessBrokers        = 256
	ecmProcessOperations     = 4096
	ecmProcessWaiters        = 8192
	ecmProfileResults        = 256
	ecmProcessResults        = 4096
	ecmMinSectionBytes       = 3
	ecmMaxSectionBytes       = 255
	ecmMaxIDBytes            = 128
	ecmMaxProvider           = 0xffffff
	ecmCompletedCacheEntries = 0
	ecmOperationLifetime     = 2 * time.Second
	ecmResultLifetime        = time.Second

	ecmMaxFrameBytes       = cccamMaxPayload
	ecmMaxCards            = cccamMaxCards
	ecmMaxProviders        = cccamMaxProviders
	ecmControlQueue        = cccamControlQueue
	ecmKeepaliveProbes     = 1
	ecmAuthenticationTests = softcamTestCapacity
	ecmReconnectDelay      = reconnectDelay
	ecmKeepaliveInterval   = keepAliveInterval
	ecmKeepaliveTimeout    = keepAliveTimeout
)

type ECMServiceIdentity struct {
	InputID         string
	InputGeneration uint64
	ONID, TSID      uint16
	ServiceID       uint16
}

type ECMRoute struct {
	CAID     uint16
	Provider uint32
}

// Handles contain no exported material. Public forwarding is implemented with
// the complete ownership backend, not a temporary successful transport stub.
type ECMClient struct {
	backend                         ecmClientBackend
	identity                        ECMServiceIdentity
	epoch                           uint64
	profileGeneration, sessionEpoch uint64
}

type ECMResult struct {
	backend ecmResultBackend
	ownerID uint64
}

// Value receivers also redact copies in interfaces and containers. Nil pointers
// use the fmt/JSON boundary; direct calls to these methods require a non-nil value.
func (ECMResult) String() string               { return "ECMResult[redacted]" }
func (ECMResult) GoString() string             { return "ECMResult[redacted]" }
func (ECMResult) MarshalJSON() ([]byte, error) { return []byte(`"ECMResult[redacted]"`), nil }

type ECMError struct {
	Code  string
	cause error
}

func ecmErrorText(code string) string {
	switch code {
	case "ecm_unsupported":
		return "ECM unsupported"
	case "ecm_invalid_request":
		return "ECM invalid request"
	case "ecm_no_route":
		return "ECM route unavailable"
	case "ca_policy_conflict":
		return "ca_policy_conflict"
	case "ecm_capacity":
		return "ECM capacity exceeded"
	case "ecm_cancelled":
		return "ECM operation cancelled"
	case "ecm_timeout":
		return "ECM operation timed out"
	case "ecm_stale":
		return "ECM ownership expired"
	case "ecm_rejected":
		return "ECM request rejected"
	case "ecm_invalid_response":
		return "ECM invalid response"
	case "ecm_session_unavailable":
		return "ECM session unavailable"
	default:
		return "ECM operation failed"
	}
}

func (e *ECMError) Error() string {
	if e == nil {
		return ecmErrorText("")
	}
	return ecmErrorText(e.Code)
}

func (e *ECMError) GoString() string { return e.Error() }

func (e *ECMError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func ecmError(code string, cause error) error {
	if ecmErrorText(code) == ecmErrorText("") {
		code = ""
	}
	return &ECMError{Code: code, cause: cause}
}

func validateECMIdentity(profileID string, identity ECMServiceIdentity) error {
	if len(profileID) > ecmMaxIDBytes || len(identity.InputID) > ecmMaxIDBytes {
		return ecmError("ecm_invalid_request", nil)
	}
	return nil
}

func validateECMRequest(section []byte, route ECMRoute) error {
	if route.Provider > ecmMaxProvider || len(section) < ecmMinSectionBytes || len(section) > ecmMaxSectionBytes {
		return ecmError("ecm_invalid_request", nil)
	}
	if section[0] != 0x80 && section[0] != 0x81 {
		return ecmError("ecm_invalid_request", nil)
	}
	declared := int(section[1]&0x0f)<<8 | int(section[2])
	if declared != len(section)-3 {
		return ecmError("ecm_invalid_request", nil)
	}
	return nil
}

type ecmToken struct {
	profileID                       string
	profileGeneration, sessionEpoch uint64
	identity                        ECMServiceIdentity
	serviceEpoch                    uint64
	cardID                          uint32
	cardRevision                    uint64
	route                           ECMRoute
	operationID                     uint64
}

type ecmCardRef struct {
	ID        uint32
	Revision  uint64
	CAID      uint16
	Providers []uint32
}

type ecmKeys struct {
	material   [16]byte
	validMask  uint8
	receivedAt time.Time
}

type ecmWireRequest struct {
	token    ecmToken
	section  []byte
	deadline time.Time
}

// Native transaction methods are bounded state mutations only. Lock order is
// owner guard, process quota, broker, native; no I/O or upward callbacks here.
type ecmNativeTransaction interface {
	Lock()
	Unlock()
	ValidateLocked(token ecmToken, now time.Time) error
	MarkWriterOwnedLocked()
}

type ecmWriterClaim interface {
	BeginWrite(tx ecmNativeTransaction) error
}

type ecmTransport interface {
	bindECMSession(epoch uint64) error
	ecmInventory() []ecmCardRef
	exchangeECM(ctx context.Context, request ecmWireRequest, claim ecmWriterClaim) (ecmKeys, error)
	abortECM(cause error)
}

type ecmTimer interface {
	C() <-chan time.Time
	Reset(time.Duration) bool
	Stop() bool
}

type ecmClock interface {
	Now() time.Time
	NewTimer(time.Duration) ecmTimer
}

type realECMClock struct{}
type realECMTimer struct{ timer *time.Timer }

func (realECMClock) Now() time.Time { return time.Now() }
func (realECMClock) NewTimer(d time.Duration) ecmTimer {
	return realECMTimer{timer: time.NewTimer(d)}
}
func (t realECMTimer) C() <-chan time.Time        { return t.timer.C }
func (t realECMTimer) Reset(d time.Duration) bool { return t.timer.Reset(d) }
func (t realECMTimer) Stop() bool                 { return t.timer.Stop() }

type ecmClientBackend interface {
	submit(client *ECMClient, ctx context.Context, section []byte, route ECMRoute) (*ECMResult, error)
	releaseService(client *ECMClient) error
	validResult(client *ECMClient, result *ECMResult) bool
	copyKeys(client *ECMClient, result *ECMResult) (even, odd [8]byte, validMask uint8, err error)
}

type ecmResultBackend interface {
	releaseResult(result *ECMResult) error
}

type ecmOwner struct {
	guard                           *sync.RWMutex
	profileID                       string
	profileGeneration, sessionEpoch uint64
	current                         bool
}

// Optional for private legacy transports; absence fails result publication and
// copy closed. Implementations are bounded native-state methods, not callbacks.
type ecmResultFence interface {
	lockECMResults()
	unlockECMResults()
	validateECMResultLocked(ecmToken) error
}

// Clear/table publication requires its own authenticated route fence, not a CW.
type ecmPublicationFence interface {
	ecmResultFence
	validateECMRouteLocked(ECMRoute) error
}

// Route validation alone cannot compare the broker's epoch without a CW token.
// This capability is implemented by the native session, not a caller override.
type ecmSessionFence interface {
	validateECMSessionLocked(uint64) error
}

var (
	ecmUnsupportedError        error = ecmFixedError{code: "ecm_unsupported"}
	ecmSessionUnavailableError error = ecmFixedError{code: "ecm_session_unavailable"}
)
