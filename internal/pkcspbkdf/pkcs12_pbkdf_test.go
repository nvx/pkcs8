// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcspbkdf

import (
	"bytes"
	"testing"
)

func TestThatPBKDFHandlesLeadingZeros(t *testing.T) {
	// This test triggers a case where I_j (in step 6C) ends up with leading zero
	// byte, meaning that len(Ijb) < v (leading zeros get stripped by big.Int).
	// This was previously causing bug whereby certain inputs would break the
	// derivation and produce the wrong output.
	key := PKCS12PBKDF(Sha1Sum, Sha1Size, 64, []byte("\xf3\x7e\x05\xb5\x18\x32\x4b\x4b"), []byte("\x00\x00"), 2048, 1, 24)
	expected := []byte("\x00\xf7\x59\xff\x47\xd1\x4d\xd0\x36\x65\xd5\x94\x3c\xb3\xc4\xa3\x9a\x25\x55\xc0\x2a\xed\x66\xe1")
	if !bytes.Equal(key, expected) {
		t.Fatalf("expected key '%x', but found '%x'", expected, key)
	}
}

func TestSha256Vector(t *testing.T) {
	key := PKCS12PBKDF(Sha256Sum, Sha256Size, 64, []byte("salt"), []byte("password"), 1024, 0, Sha256Size)
	expected := []byte("\x46\xFB\x1E\x99\xAA\x49\x5B\x54\x8F\x67\x30\x27\x82\xAF\xEF\x47\x11\x49\x74\x37\xF0\x84\xC6\x6C\xB2\x1B\x37\xAE\xB8\x20\x6E\xF1")
	if !bytes.Equal(key, expected) {
		t.Fatalf("expected key '%x', but found '%x'", expected, key)
	}
}
