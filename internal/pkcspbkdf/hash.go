package pkcspbkdf

import (
	"crypto/md5"  //nolint:gosec // compatibility
	"crypto/sha1" //nolint:gosec // compatibility
	"crypto/sha256"
)

const Md5Size = md5.Size

// Md5Sum returns the MD5 hash of in.
func Md5Sum(in []byte) []byte {
	sum := md5.Sum(in) //nolint:gosec // compatibility
	return sum[:]
}

const Sha1Size = sha1.Size

// Sha1Sum returns the SHA-1 hash of in.
func Sha1Sum(in []byte) []byte {
	sum := sha1.Sum(in) //nolint:gosec // compatibility
	return sum[:]
}

const Sha256Size = sha256.Size

// Sha256Sum returns the SHA-256 hash of in.
func Sha256Sum(in []byte) []byte {
	sum := sha256.Sum256(in)
	return sum[:]
}
