// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import "errors"

// DecodeErr records an error and place when it is occurred.
//
//nolint:errname
type DecodeErr struct {
	Place   DecodeErrPlace
	Message string
}

// IsInvalidCookie returns true if error means that magic cookie
// value is invalid.
func (e DecodeErr) IsInvalidCookie() bool {
	return e.Place == DecodeErrPlace{"message", "cookie"}
}

// IsPlaceParent reports if error place parent is p.
func (e DecodeErr) IsPlaceParent(p string) bool {
	return e.Place.Parent == p
}

// IsPlaceChildren reports if error place children is c.
func (e DecodeErr) IsPlaceChildren(c string) bool {
	return e.Place.Children == c
}

// IsPlace reports if error place is p.
func (e DecodeErr) IsPlace(p DecodeErrPlace) bool {
	return e.Place == p
}

// DecodeErrPlace records a place where error is occurred.
type DecodeErrPlace struct {
	Parent   string
	Children string
}

func (p DecodeErrPlace) String() string {
	return p.Parent + "/" + p.Children
}

func (e DecodeErr) Error() string {
	return "BadFormat for " + e.Place.String() + ": " + e.Message
}

func newDecodeErr(parent, children, message string) *DecodeErr {
	return &DecodeErr{
		Place:   DecodeErrPlace{Parent: parent, Children: children},
		Message: message,
	}
}

func newAttrDecodeErr(children, message string) *DecodeErr {
	return newDecodeErr("attribute", children, message)
}

// ErrAttributeSizeInvalid means that decoded attribute size is invalid.
var ErrAttributeSizeInvalid = errors.New("attribute size is invalid")

// ErrAttributeSizeOverflow means that decoded attribute size is too big.
var ErrAttributeSizeOverflow = errors.New("attribute size overflow")

// errInvalidErrorCode means that ErrorCode can't be encoded in ERROR-CODE.
var errInvalidErrorCode = errors.New("invalid ErrorCode")

// ErrAttributeAfterIntegrity means that an attribute not permitted by
// RFC 8489 was found after MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256.
// After MESSAGE-INTEGRITY only MESSAGE-INTEGRITY-SHA256 and FINGERPRINT may
// follow; after MESSAGE-INTEGRITY-SHA256 (without MESSAGE-INTEGRITY) only
// FINGERPRINT may follow. Anything else is not covered by the integrity
// check and is rejected by strict decoding.
var ErrAttributeAfterIntegrity = errors.New("attribute after MESSAGE-INTEGRITY/MESSAGE-INTEGRITY-SHA256")

// ErrDuplicateIntegrity means that MESSAGE-INTEGRITY or
// MESSAGE-INTEGRITY-SHA256 appeared more than once in a message.
var ErrDuplicateIntegrity = errors.New("duplicate MESSAGE-INTEGRITY/MESSAGE-INTEGRITY-SHA256 attribute")

// ErrFingerprintNotLast means that an attribute was found after the
// FINGERPRINT attribute. FINGERPRINT must be the last attribute in
// a message.
var ErrFingerprintNotLast = errors.New("attribute after FINGERPRINT: FINGERPRINT must be last")

// ErrDuplicateFingerprint means that FINGERPRINT appeared more than
// once in a message.
var ErrDuplicateFingerprint = errors.New("duplicate FINGERPRINT attribute")

// ErrUnknownRequiredAttribute means that a message contained an attribute
// from the comprehension-required range (0x0000-0x7FFF) that is not known
// to this library.
var ErrUnknownRequiredAttribute = errors.New("unknown comprehension-required attribute")
