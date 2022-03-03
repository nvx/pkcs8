package pkcs8

import (
	"crypto/cipher"
	"crypto/des" //nolint:gosec // compatibility
	"encoding/asn1"
	"errors"
	"github.com/youmark/pkcs8/internal/pkcspbkdf"
	"github.com/youmark/pkcs8/internal/rc2"
)

var (
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3})
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 6})
	oidPBEWithMD5AndDESCBC           = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 5, 3})
)

var shaWithTripleDESCBC = cipherWithBlock{
	ivSize:   des.BlockSize,
	keySize:  24,
	newBlock: des.NewTripleDESCipher,
	oid:      oidPBEWithSHAAnd3KeyTripleDESCBC,
}

var shaWith40BitRC2CBC = cipherWithBlock{
	ivSize:  rc2.BlockSize,
	keySize: 5,
	newBlock: func(key []byte) (cipher.Block, error) {
		return rc2.New(key, len(key)*8)
	},
	oid: oidPBEWithSHAAnd40BitRC2CBC,
}

var md5WithDESCBC = cipherWithBlock{
	ivSize:   des.BlockSize,
	keySize:  8,
	newBlock: des.NewCipher,
	oid:      oidPBEWithMD5AndDESCBC,
}

type pbeKDFParameters interface {
	KDFParameters
	DeriveIV(password []byte, size int) (key []byte, err error)
}

type sha1PbeParams struct {
	Salt       []byte
	Iterations int
}

type md5Pkcs5PbeParams struct {
	Salt       []byte
	Iterations int
}

func (p sha1PbeParams) pbkdf(password []byte, size int, id byte) (key []byte, err error) {
	return pkcspbkdf.PKCS12PBKDF(pkcspbkdf.Sha1Sum, pkcspbkdf.Sha1Size, 64, p.Salt, password, p.Iterations, id, size), nil
}

func (p sha1PbeParams) DeriveKey(password []byte, size int) (key []byte, err error) {
	return p.pbkdf(password, size, 1)
}

func (p sha1PbeParams) DeriveIV(password []byte, size int) (key []byte, err error) {
	return p.pbkdf(password, size, 2)
}

func (p md5Pkcs5PbeParams) pbkdf(password []byte, size, part int) (key []byte, err error) {
	key = pkcspbkdf.PKCS5PBKDF1(pkcspbkdf.Md5Sum, p.Salt, password, p.Iterations, size)
	return key[part*8 : (part*8)+8], nil
}

func (p md5Pkcs5PbeParams) DeriveKey(password []byte, size int) (key []byte, err error) {
	return p.pbkdf(password, 16, 0)
}

func (p md5Pkcs5PbeParams) DeriveIV(password []byte, size int) (key []byte, err error) {
	return p.pbkdf(password, 16, 1)
}

func decryptPBE(privKey encryptedPrivateKeyInfo, password []byte) ([]byte, KDFParameters, error) {
	var origPassword bool
	var params pbeKDFParameters
	var cipherType Cipher
	switch {
	case privKey.EncryptionAlgorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		params = &sha1PbeParams{}
		cipherType = shaWithTripleDESCBC
	case privKey.EncryptionAlgorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		params = &sha1PbeParams{}
		cipherType = shaWith40BitRC2CBC
	case privKey.EncryptionAlgorithm.Algorithm.Equal(oidPBEWithMD5AndDESCBC):
		params = &md5Pkcs5PbeParams{}
		cipherType = md5WithDESCBC
		origPassword = true
	default:
		return nil, nil, errors.New("pkcs8: unsupported algorithm: " + privKey.EncryptionAlgorithm.Algorithm.String())
	}

	if !origPassword {
		var err error
		password, err = bmpStringZeroTerminated(string(password))
		if err != nil {
			return nil, nil, err
		}
	}

	err := unmarshal(privKey.EncryptionAlgorithm.Parameters.FullBytes, params)
	if err != nil {
		return nil, nil, err
	}

	symKey, err := params.DeriveKey(password, cipherType.KeySize())
	if err != nil {
		return nil, nil, err
	}

	iv, err := params.DeriveIV(password, cipherType.IVSize())
	if err != nil {
		return nil, nil, err
	}

	encryptedKey := privKey.EncryptedData
	decryptedKey, err := cipherType.Decrypt(symKey, iv, encryptedKey)
	if err != nil {
		return nil, nil, err
	}

	return decryptedKey, params, nil
}
