// Copyright 2022 - Sarjono Mukti Aji. All rights reserved.
// This code is licensed under MIT license (see LICENSE.txt for details).

// Package totp implement TOTP (RFC-6238) based on https://datatracker.ietf.org/doc/html/rfc6238#appendix-A
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"
)

type TOTP struct {
	digitLen   int              // string length of TOTP code
	timeWindow int              // in seconds
	hasher     func() hash.Hash // hash function to be used for HMAC
}

// NewSHA1 construct TOTP using SHA1 as the hash function.
// Common digitLen is usually 6 and the time window is 30 (seconds).
func NewSHA1(digitLen, timeWindow int) (*TOTP, error) {
	return newWithHasher(digitLen, timeWindow, sha1.New)
}

// NewSHA256 construct TOTP using SHA256 as the hash function.
func NewSHA256(digitLen, timeWindow int) (*TOTP, error) {
	return newWithHasher(digitLen, timeWindow, sha256.New)
}

// NewSHA512 construct TOTP using SHA512 as the hash function.
func NewSHA512(digitLen, timeWindow int) (*TOTP, error) {
	return newWithHasher(digitLen, timeWindow, sha512.New)
}

func newWithHasher(digitLen, timeWindow int, hasher func() hash.Hash) (*TOTP, error) {
	if digitLen < 1 || digitLen > 8 {
		return nil, fmt.Errorf("totp: digitLen only allow 1 to 8, inclusive, got %d", digitLen)
	}
	if timeWindow < 1 {
		return nil, fmt.Errorf("totp: timeWindow should be more than 0, got %d", timeWindow)
	}
	return &TOTP{digitLen: digitLen, timeWindow: timeWindow, hasher: hasher}, nil
}

// OTP generate TOTP digit code at given time using given key.
func (t *TOTP) OTP(key []byte, at time.Time) (string, error) {
	if at.Unix() < 1 {
		return "", fmt.Errorf("totp: unsupported time: %s", at.String())
	}
	counter := at.Unix() / int64(t.timeWindow)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter))
	h := hmac.New(t.hasher, key)
	if _, err := h.Write(b); err != nil {
		return "", err
	}
	sum := h.Sum(nil)
	idx := sum[h.Size()-1] & 0xf
	bin := int((sum[idx])&0x7f)<<24 | int((sum[idx+1])&0xff)<<16 | int((sum[idx+2])&0xff)<<8 | int(sum[idx+3])&0xff
	bin %= int(math.Pow10(t.digitLen))
	otp := strconv.FormatInt(int64(bin), 10)
	if len(otp) < t.digitLen {
		otp = strings.Repeat("0", t.digitLen-len(otp)) + otp
	}
	return otp, nil
}
