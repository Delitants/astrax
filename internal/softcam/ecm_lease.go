// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) Delitants

package softcam

import "time"

type ECMLeaseInfo struct {
	ReceivedAt, ExpiresAt time.Time
	ValidMask             uint8
}

type ECMBindingInfo struct {
	Identity                                      ECMServiceIdentity
	ProfileGeneration, SessionEpoch, ServiceEpoch uint64
}

func (ECMLeaseInfo) String() string                 { return "ECMLeaseInfo[redacted]" }
func (ECMLeaseInfo) GoString() string               { return "ECMLeaseInfo[redacted]" }
func (ECMLeaseInfo) MarshalJSON() ([]byte, error)   { return []byte(`"ECMLeaseInfo[redacted]"`), nil }
func (ECMBindingInfo) String() string               { return "ECMBindingInfo[redacted]" }
func (ECMBindingInfo) GoString() string             { return "ECMBindingInfo[redacted]" }
func (ECMBindingInfo) MarshalJSON() ([]byte, error) { return []byte(`"ECMBindingInfo[redacted]"`), nil }

// The public ownership additions use the real broker only. Legacy adapters keep
// their existing Submit/Copy/Release contract, without gaining new capabilities.
func ecmClientBroker(c *ECMClient) (*ecmBroker, error) {
	if c == nil || c.backend == nil {
		return nil, ecmStaleError
	}
	b, ok := c.backend.(*ecmBroker)
	if !ok {
		return nil, ecmUnsupportedError
	}
	if b == nil || b.owner == nil || b.owner.guard == nil || b.quota == nil || b.clock == nil {
		return nil, ecmStaleError
	}
	return b, nil
}

// A manager forwarder retains its historical concrete type. Check its actual
// dependency before even entering the native fence: forwarding methods are not
// evidence that a legacy result-only transport implements publication.
func ecmPublicationFences(transport ecmTransport) (ecmPublicationFence, ecmSessionFence, bool) {
	if wrapped, ok := transport.(*managerECMAttachmentFencedTransport); ok {
		if wrapped == nil || wrapped.managerECMAttachmentTransport == nil {
			return nil, nil, false
		}
		if _, ok := wrapped.ecmTransport.(ecmPublicationFence); !ok {
			return nil, nil, false
		}
		if _, ok := wrapped.ecmTransport.(ecmSessionFence); !ok {
			return nil, nil, false
		}
	}
	fence, routeOK := transport.(ecmPublicationFence)
	session, epochOK := transport.(ecmSessionFence)
	return fence, session, routeOK && epochOK
}

func (b *ecmBroker) clientScopeLocked(c *ECMClient) bool {
	return b.currentLocked() && b.clientBindingLocked(c) != nil &&
		c.profileGeneration == b.owner.profileGeneration && c.sessionEpoch == b.owner.sessionEpoch
}

// Caller already holds owner -> quota -> broker -> native. Only the existing
// owner is examined/dropped; no copy, extra backing ref or fresh receipt is made.
func (b *ecmBroker) leaseBackingLocked(c *ECMClient, r *ECMResult, now time.Time, fence ecmResultFence) (*ecmKeyBacking, error) {
	if !b.clientScopeLocked(c) {
		return nil, ecmStaleError
	}
	k := b.resultLocked(c, r, now)
	if k == nil {
		return nil, ecmStaleError
	}
	if k.token.identity != c.identity || k.token.serviceEpoch != c.epoch ||
		k.responseAt.IsZero() || k.responseAt.After(now) || k.keys.receivedAt != k.responseAt ||
		k.expires != k.responseAt.Add(ecmResultLifetime) || k.keys.validMask == 0 || k.keys.validMask & ^uint8(3) != 0 ||
		fence.validateECMResultLocked(k.token) != nil {
		b.dropResultLocked(r.ownerID)
		return nil, ecmStaleError
	}
	if !b.clock.Now().Before(k.expires) {
		b.dropResultLocked(r.ownerID)
		return nil, ecmStaleError
	}
	return k, nil
}

func (c *ECMClient) LeaseInfo(r *ECMResult) (ECMLeaseInfo, error) {
	b, err := ecmClientBroker(c)
	if err != nil {
		return ECMLeaseInfo{}, err
	}
	b.lock()
	fence, ok := b.transport.(ecmResultFence)
	if !ok {
		b.unlock()
		return ECMLeaseInfo{}, ecmUnsupportedError
	}
	fence.lockECMResults()
	// Now is sampled after the actual native wait, never before it.
	k, err := b.leaseBackingLocked(c, r, b.clock.Now(), fence)
	var info ECMLeaseInfo
	if err == nil {
		info = ECMLeaseInfo{ReceivedAt: k.responseAt, ExpiresAt: k.expires, ValidMask: k.keys.validMask}
	}
	fence.unlockECMResults()
	b.unlock()
	b.notify()
	return info, err
}

func (c *ECMClient) BindingInfo() (ECMBindingInfo, error) {
	b, err := ecmClientBroker(c)
	if err != nil {
		return ECMBindingInfo{}, err
	}
	b.lock()
	fence, session, ok := ecmPublicationFences(b.transport)
	if !ok {
		b.unlock()
		return ECMBindingInfo{}, ecmUnsupportedError
	}
	fence.lockECMResults()
	var info ECMBindingInfo
	if !b.clientScopeLocked(c) {
		err = ecmStaleError
	} else if err = session.validateECMSessionLocked(b.owner.sessionEpoch); err == nil {
		info = ECMBindingInfo{Identity: c.identity, ProfileGeneration: c.profileGeneration, SessionEpoch: c.sessionEpoch, ServiceEpoch: c.epoch}
	}
	fence.unlockECMResults()
	b.unlock()
	return info, err
}
