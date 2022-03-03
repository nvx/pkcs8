// Copyright 2015, 2018, 2019 Opsmate, Inc. All rights reserved.
// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs8

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"
)

var sha1WithTripleDES = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3})

func TestPbDecrypterFor(t *testing.T) {
	params, _ := asn1.Marshal(sha1PbeParams{
		Salt:       []byte{1, 2, 3, 4, 5, 6, 7, 8},
		Iterations: 2048,
	})
	alg := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier([]int{1, 2, 3}),
		Parameters: asn1.RawValue{
			FullBytes: params,
		},
	}

	pass, _ := bmpStringZeroTerminated("Sesame open")

	_, _, err := decryptPBE(encryptedPrivateKeyInfo{
		EncryptionAlgorithm: alg,
		EncryptedData:       nil,
	}, pass)
	if err == nil {
		t.Errorf("expected not implemented error")
	}
}

var pbDecryptTests = []struct {
	name     string
	in       []byte
	expected []byte
}{
	{
		name:     "7 padding bytes",
		in:       []byte("\x33\x73\xf3\x9f\xda\x49\xae\xfc\xa0\x9a\xdf\x5a\x58\xa0\xea\x46"),
		expected: []byte("A secret!"),
	},
	{
		name:     "8 padding bytes",
		in:       []byte("\x33\x73\xf3\x9f\xda\x49\xae\xfc\x96\x24\x2f\x71\x7e\x32\x3f\xe7"),
		expected: []byte("A secret"),
	},
}

func TestDecryptPBE(t *testing.T) {
	for _, test := range pbDecryptTests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			alg := pkix.AlgorithmIdentifier{
				Algorithm: sha1WithTripleDES,
				Parameters: makeRawParams(sha1PbeParams{
					Salt:       []byte("\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8"),
					Iterations: 4096,
				}),
			}

			password := []byte("sesame")

			plaintext, _, err := decryptPBE(encryptedPrivateKeyInfo{
				EncryptionAlgorithm: alg,
				EncryptedData:       test.in,
			}, password)
			if err != nil {
				t.Errorf("got error %q", err)
				return
			}

			if !bytes.Equal(plaintext, test.expected) {
				t.Errorf("got %x, but wanted %x", plaintext, test.expected)
			}
		})
	}
}

func makeRawParams(p pbeKDFParameters) (raw asn1.RawValue) {
	asn1Bytes, err := asn1.Marshal(p)
	if err != nil {
		panic(err)
	}
	_, err = asn1.Unmarshal(asn1Bytes, &raw)
	if err != nil {
		panic(err)
	}
	return
}
