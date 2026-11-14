// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package stun

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newStrictTestMessage(t *testing.T) *Message {
	t.Helper()

	m := New()
	m.SetType(BindingRequest)
	require.NoError(t, m.NewTransactionID())
	m.WriteHeader()
	m.Add(AttrUsername, []byte("user"))

	return m
}

func TestDecodeStrict(t *testing.T) {
	t.Run("Valid", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, NewShortTermIntegrity("pass").AddTo(m))
		require.NoError(t, Fingerprint.AddTo(m))

		decoded := New()
		require.NoError(t, DecodeStrict(m.Raw, decoded))
		assert.Equal(t, m.Type, decoded.Type)
		assert.Equal(t, len(m.Attributes), len(decoded.Attributes))
	})

	t.Run("ValidFullChain", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, NewShortTermIntegrity("pass").AddTo(m))
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))
		require.NoError(t, Fingerprint.AddTo(m))

		require.NoError(t, DecodeStrict(m.Raw, New()))
	})

	t.Run("NilMessage", func(t *testing.T) {
		assert.ErrorIs(t, DecodeStrict([]byte{0}, nil), ErrDecodeToNil)
	})

	t.Run("UnknownOptionalAllowed", func(t *testing.T) {
		m := newStrictTestMessage(t)
		m.Add(AttrType(0x9000), []byte{1, 2, 3, 4}) // unknown comprehension-optional

		decoded := New()
		require.NoError(t, DecodeStrict(m.Raw, decoded))
		assert.Equal(t, len(m.Attributes), len(decoded.Attributes))
	})

	t.Run("LenientDecodeUnchanged", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, NewShortTermIntegrity("pass").AddTo(m))
		m.Add(AttrSoftware, []byte("after-integrity"))

		decoded := New()
		require.NoError(t, Decode(m.Raw, decoded))
		// Lenient Decode silently drops the attribute after MESSAGE-INTEGRITY.
		_, ok := decoded.Attributes.Get(AttrSoftware)
		assert.False(t, ok)
	})
}

func TestDecodeStrictIntegrityCoverage(t *testing.T) {
	t.Run("AttributeAfterIntegrity", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, NewShortTermIntegrity("pass").AddTo(m))
		m.Add(AttrSoftware, []byte("not-covered"))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrAttributeAfterIntegrity)
	})

	t.Run("AttributeAfterIntegritySHA256Only", func(t *testing.T) {
		m := newStrictTestMessage(t)
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))
		m.Add(AttrSoftware, []byte("not-covered"))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrAttributeAfterIntegrity)
	})

	t.Run("IntegrityAfterIntegritySHA256", func(t *testing.T) {
		// MESSAGE-INTEGRITY must precede MESSAGE-INTEGRITY-SHA256.
		m := newStrictTestMessage(t)
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))
		require.NoError(t, NewShortTermIntegrity("pass").AddTo(m))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrAttributeAfterIntegrity)
	})

	t.Run("DuplicateIntegrity", func(t *testing.T) {
		m := newStrictTestMessage(t)
		integrity := NewShortTermIntegrity("pass")
		require.NoError(t, integrity.AddTo(m))
		require.NoError(t, integrity.AddTo(m))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrDuplicateIntegrity)
	})

	t.Run("DuplicateIntegritySHA256", func(t *testing.T) {
		m := newStrictTestMessage(t)
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))
		m.Add(AttrMessageIntegritySHA256, make([]byte, 32))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrDuplicateIntegrity)
	})
}

func TestDecodeStrictFingerprintOrdering(t *testing.T) {
	t.Run("FingerprintNotLast", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, Fingerprint.AddTo(m))
		m.Add(AttrSoftware, []byte("after-fingerprint"))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrFingerprintNotLast)
	})

	t.Run("DuplicateFingerprint", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, Fingerprint.AddTo(m))
		require.NoError(t, Fingerprint.AddTo(m))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrDuplicateFingerprint)
	})

	t.Run("IntegrityAfterFingerprint", func(t *testing.T) {
		m := newStrictTestMessage(t)
		require.NoError(t, Fingerprint.AddTo(m))
		m.Add(AttrMessageIntegrity, make([]byte, messageIntegritySize))

		err := DecodeStrict(m.Raw, New())
		assert.ErrorIs(t, err, ErrFingerprintNotLast)
	})
}

func TestDecodeStrictUnknownRequired(t *testing.T) {
	m := newStrictTestMessage(t)
	m.Add(AttrType(0x7777), []byte{1, 2, 3, 4}) // unknown comprehension-required

	err := DecodeStrict(m.Raw, New())
	assert.ErrorIs(t, err, ErrUnknownRequiredAttribute)
	// Lenient Decode accepts unknown comprehension-required attributes.
	assert.NoError(t, Decode(m.Raw, New()))
}
