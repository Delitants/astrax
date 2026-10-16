// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import (
	"context"
	"errors"
	"sync"
	"time"

	"astrax/internal/model"
)

var ErrTestBusy = errors.New("softcam Test capacity exhausted")

// The structural marker lets the store retain cleanup evidence separately from
// ordinary login failures and cancellation, without widening runtime factories.
type testSessionCloseError struct{ cause error }

func (e *testSessionCloseError) Error() string            { return "softcam Test session close failed" }
func (e *testSessionCloseError) Unwrap() error            { return e.cause }
func (e *testSessionCloseError) SessionCloseError() error { return e }

type connectionTester struct {
	nativeNewcamdFactory bool
	slots                chan struct{}
	opener               func(context.Context, model.Softcam) (session, time.Duration, error)
}

func newConnectionTester(capacity int, opener func(context.Context, model.Softcam) (session, time.Duration, error)) (*connectionTester, error) {
	if capacity <= 0 || opener == nil {
		return nil, errors.New("complete Test opener and positive capacity required")
	}
	return &connectionTester{slots: make(chan struct{}, capacity), opener: opener}, nil
}

var defaultConnectionTester = func() *connectionTester {
	t, _ := newConnectionTester(softcamTestCapacity, openProfileSessionContext)
	t.nativeNewcamdFactory = true
	return t
}()

func TestConnectionContext(ctx context.Context, profile model.Softcam) (*model.SoftcamTestResult, error) {
	return defaultConnectionTester.Test(ctx, profile)
}

// Whitelist both the public copy and code; wrapped private causes and forged
// ProtocolError codes never supply public strings.
func safeCCcamError(err error) (string, string) {
	if err.Error() == "CCcam authentication is not implemented; connections are disabled" {
		return "CCcam authentication is not implemented; connections are disabled", "unsupported_protocol"
	}
	var pe *ProtocolError
	code := "protocol_error"
	if errors.As(err, &pe) {
		switch pe.Code {
		case "invalid_configuration", "dial_failed", "login_rejected", "login_timeout", "unsupported_protocol", "invalid_frame", "inventory_limit", "keepalive_timeout", "probe_busy", "session_closed", "cancelled":
			code = pe.Code
		}
	}
	if errors.Is(err, context.Canceled) {
		code = "cancelled"
	}
	return (&ProtocolError{Code: code}).Error(), code
}

func cccamMetadata(status SessionStatus) (*bool, *bool, *int) {
	auth, no, cards := status.Authenticated, false, status.CardsObserved
	return &auth, &no, &cards
}

// A profile label or metadata-only wrapper does not promise native ownership.
func isNativeNewcamd(s session) bool {
	_, ok := s.(interface {
		nativeNewcamd()
		sessionState() (SessionStatus, error)
	})
	return ok
}

// CCcam has no inventory-complete message. Give the native reader a short
// observation window, not a new login budget or a promise of complete cards.
func observeCCcamTestInventory(ctx context.Context, s *cccamSession) (SessionStatus, error) {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return SessionStatus{}, ctx.Err()
	case <-s.done:
	case <-timer.C:
	}
	if err := ctx.Err(); err != nil {
		return SessionStatus{}, err
	}
	return s.sessionState()
}

func (t *connectionTester) Test(ctx context.Context, profile model.Softcam) (result *model.SoftcamTestResult, resultErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case t.slots <- struct{}{}:
	default:
		return nil, ErrTestBusy
	}
	defer func() { <-t.slots }()
	profile.Type = normalizeSoftcamType(profile.Type)
	cccam := profile.Type == "cccam"
	newcamd := false
	failedNativeOpen := profile.Type == "newcamd" && t.nativeNewcamdFactory
	result = &model.SoftcamTestResult{Protocol: profile.Type}
	fail := func(err error) {
		result.Success = false
		result.Connected = false
		if cccam || newcamd || failedNativeOpen {
			result.CAIDs = nil
			result.Authenticated, result.DescramblingSupported, result.CardsObserved = cccamMetadata(SessionStatus{})
			if cccam {
				result.Error, result.ErrorCode = safeCCcamError(err)
			} else {
				result.Error, result.ErrorCode = safeNewcamdError(err)
			}
		} else {
			result.Error = err.Error()
		}
	}
	var timeout time.Duration
	if cccam {
		var err error
		timeout, err = validateCCcamProfile(profile)
		if err != nil {
			fail(err)
			return result, nil
		}
	}
	// Only CCcam adds an aggregate Test budget and a liveness exchange.
	// Newcamd's native opener owns its separate dial/login/discovery budgets.
	var work context.Context
	var cancel context.CancelFunc
	if cccam {
		work, cancel = context.WithTimeout(ctx, timeout+keepAliveTimeout)
	} else {
		work, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	sess, latency, err := t.opener(work, profile)
	nativeCCcam, _ := sess.(*cccamSession)
	newcamd = profile.Type == "newcamd" && isNativeNewcamd(sess)
	failedNativeOpen = failedNativeOpen && sess == nil
	if sess != nil {
		var closeOnce sync.Once
		var closeErr error
		closeSession := func() { closeOnce.Do(func() { closeErr = sess.Close() }) }
		hookDone := make(chan struct{})
		stop := func() bool { return true }
		if cccam || newcamd {
			stop = context.AfterFunc(work, func() { defer close(hookDone); closeSession() })
		}
		defer func() {
			if !stop() {
				<-hookDone
			}
			closeSession()
			if closeErr != nil {
				fail(closeErr)
				resultErr = &testSessionCloseError{cause: closeErr}
			}
			if work.Err() != nil {
				fail(work.Err())
				if closeErr != nil {
					resultErr = errors.Join(work.Err(), &testSessionCloseError{cause: closeErr})
				} else {
					resultErr = work.Err()
				}
			}
		}()
	}
	if work.Err() != nil {
		fail(work.Err())
		return result, work.Err()
	}
	if err != nil {
		fail(err)
		return result, nil
	}
	if sess == nil {
		fail(errors.New("session opener returned no session"))
		return result, nil
	}
	if cccam {
		deadline, _ := work.Deadline()
		_, err = sess.KeepAlive(min(keepAliveTimeout, max(time.Until(deadline), 0)))
		if err != nil {
			fail(err)
			return result, nil
		}
		provider, ok := sess.(sessionStatusProvider)
		if !ok {
			fail(protocolError("unsupported_protocol", nil))
			return result, nil
		}
		var status SessionStatus
		if nativeCCcam != nil {
			status, err = observeCCcamTestInventory(work, nativeCCcam)
			if err != nil {
				fail(err)
				return result, nil
			}
		} else {
			status = provider.SessionStatus()
		}
		result.Authenticated, result.DescramblingSupported, result.CardsObserved = cccamMetadata(status)
		if !status.Authenticated {
			fail(protocolError("session_closed", nil))
			return result, nil
		}
	}
	if newcamd {
		status, err := sess.(sessionStateProvider).sessionState()
		if err != nil || !status.Authenticated {
			if err == nil {
				err = newcamdError("session_closed", nil)
			}
			fail(err)
			return result, nil
		}
		result.Authenticated, result.DescramblingSupported, result.CardsObserved = cccamMetadata(status)
	}
	result.Success = true
	result.Connected = true
	result.LatencyMS = latency.Milliseconds()
	if caids, ok := sess.(caidSession); ok {
		values, err := caids.GetCAIDs()
		if err != nil && (cccam || newcamd) {
			fail(err)
			return result, nil
		}
		if err == nil && len(values) > 0 {
			result.CAIDs = append([]string(nil), values...)
		}
	}
	// Inventory access is a separate native-state sample. Recheck terminal state
	// after it so a retired session cannot turn an inventory error into success.
	if newcamd || (cccam && nativeCCcam != nil) {
		status, err := sess.(sessionStateProvider).sessionState()
		if err != nil || !status.Authenticated {
			if err == nil {
				if cccam {
					err = protocolError("session_closed", nil)
				} else {
					err = newcamdError("session_closed", nil)
				}
			}
			fail(err)
		} else {
			result.Authenticated, result.DescramblingSupported, result.CardsObserved = cccamMetadata(status)
		}
	}
	return result, nil
}
