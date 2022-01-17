// Copyright 2022 - Sarjono Mukti Aji. All rights reserved.
// This code is licensed under MIT license (see LICENSE.txt for details).

package totp

import (
	"testing"
	"time"
)

func TestExample(t *testing.T) {
	totp, err := NewSHA1(6, 30)
	if err != nil {
		t.Fatal(err)
	}
	// DON'T USE ANY OF THESE KEYS IN ACTUAL IMPLEMENTATION.
	key := []byte("12345678901234567890")
	otp, err := totp.OTP(key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Current OTP: %s", otp)
}

func TestTOTP_OTP(t *testing.T) {
	t.Run("Invalid construct params", func(t *testing.T) {
		type ts struct {
			digitLen, window int
			expectErr        bool
		}
		tt := []ts{
			// invalid time window
			{digitLen: 6, window: 0, expectErr: true},
		}
		// invalid digit length
		for i := 0; i < 1; i++ {
			tt = append(tt, ts{
				digitLen:  i,
				window:    30,
				expectErr: true,
			})
		}
		for i := 1; i <= 8; i++ {
			tt = append(tt, ts{
				digitLen:  i,
				window:    30,
				expectErr: false,
			})
		}
		for i := 9; i < 12; i++ {
			tt = append(tt, ts{
				digitLen:  i,
				window:    30,
				expectErr: true,
			})
		}
		for _, tc := range tt {
			_, err := NewSHA1(tc.digitLen, tc.window)
			if tc.expectErr && err == nil {
				t.Fatalf("digitLen %d and window %d expect error, got %v", tc.digitLen, tc.window, err)
			}
		}
	})
	t.Run("Invalid OTP time", func(t *testing.T) {
		tt := []struct {
			at        time.Time
			otp       string
			expectErr bool
		}{
			{at: time.Unix(0, 0), otp: "", expectErr: true},
			{at: time.Time{}, otp: "", expectErr: true}, // zero time
		}
		for _, tc := range tt {
			totp, err := NewSHA1(6, 30)
			if err != nil {
				t.Fatalf("should not error, got %v", err)
			}
			otp, err := totp.OTP([]byte("12345678901234567890"), tc.at)
			if otp != tc.otp {
				t.Fatalf("expect \"%s\", got \"%v\"", tc.otp, otp)
			}
			if tc.expectErr && err == nil {
				t.Fatalf("expect error, got %v", err)
			}
		}
	})
}

func TestNewSHA1(t *testing.T) {
	tt := []struct {
		k   string
		d   int
		p   int
		ts  int64
		otp string
	}{
		// values based on https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
		{k: "12345678901234567890", d: 8, p: 30, ts: 59, otp: "94287082"},
		{k: "12345678901234567890", d: 8, p: 30, ts: 1111111109, otp: "07081804"},
		{k: "12345678901234567890", d: 8, p: 30, ts: 1111111111, otp: "14050471"},
		{k: "12345678901234567890", d: 8, p: 30, ts: 1234567890, otp: "89005924"},
		{k: "12345678901234567890", d: 8, p: 30, ts: 2000000000, otp: "69279037"},
		{k: "12345678901234567890", d: 8, p: 30, ts: 20000000000, otp: "65353130"},
	}
	for _, tc := range tt {
		totp, err := NewSHA1(tc.d, tc.p)
		if err != nil {
			t.Fatalf("should not error, got %v", err)
		}
		otp, err := totp.OTP([]byte(tc.k), time.Unix(tc.ts, 0))
		if err != nil {
			t.Fatalf("should not error, got %v", err)
		}
		if otp != tc.otp {
			t.Errorf("expect %v, got %v", tc.otp, otp)
		}
	}
}

func TestNewSHA256(t *testing.T) {
	tt := []struct {
		k   string
		d   int
		p   int
		ts  int64
		otp string
	}{
		// values based on https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
		{k: "12345678901234567890123456789012", d: 8, p: 30, ts: 59, otp: "46119246"},
		{k: "12345678901234567890123456789012", d: 8, p: 30, ts: 1111111109, otp: "68084774"},
		{k: "12345678901234567890123456789012", d: 8, p: 30, ts: 1111111111, otp: "67062674"},
		{k: "12345678901234567890123456789012", d: 8, p: 30, ts: 1234567890, otp: "91819424"},
		{k: "12345678901234567890123456789012", d: 8, p: 30, ts: 2000000000, otp: "90698825"},
		{k: "12345678901234567890123456789012", d: 8, p: 30, ts: 20000000000, otp: "77737706"},
	}
	for _, tc := range tt {
		totp, err := NewSHA256(tc.d, tc.p)
		if err != nil {
			t.Fatalf("should not error, got %v", err)
		}
		otp, err := totp.OTP([]byte(tc.k), time.Unix(tc.ts, 0))
		if err != nil {
			t.Fatalf("should not error, got %v", err)
		}
		if otp != tc.otp {
			t.Fatalf("expect %v, got %v", tc.otp, otp)
		}
	}
}

func TestNewSHA512(t *testing.T) {
	tt := []struct {
		k   string
		d   int
		p   int
		ts  int64
		otp string
	}{
		// values based on https://datatracker.ietf.org/doc/html/rfc6238#appendix-B
		{k: "1234567890123456789012345678901234567890123456789012345678901234", d: 8, p: 30, ts: 59, otp: "90693936"},
		{k: "1234567890123456789012345678901234567890123456789012345678901234", d: 8, p: 30, ts: 1111111109, otp: "25091201"},
		{k: "1234567890123456789012345678901234567890123456789012345678901234", d: 8, p: 30, ts: 1111111111, otp: "99943326"},
		{k: "1234567890123456789012345678901234567890123456789012345678901234", d: 8, p: 30, ts: 1234567890, otp: "93441116"},
		{k: "1234567890123456789012345678901234567890123456789012345678901234", d: 8, p: 30, ts: 2000000000, otp: "38618901"},
		{k: "1234567890123456789012345678901234567890123456789012345678901234", d: 8, p: 30, ts: 20000000000, otp: "47863826"},
	}
	for _, tc := range tt {
		totp, err := NewSHA512(tc.d, tc.p)
		if err != nil {
			t.Fatalf("should not error, got %v", err)
		}
		otp, err := totp.OTP([]byte(tc.k), time.Unix(tc.ts, 0))
		if err != nil {
			t.Fatalf("should not error, got %v", err)
		}
		if otp != tc.otp {
			t.Fatalf("expect %v, got %v", tc.otp, otp)
		}
	}
}
