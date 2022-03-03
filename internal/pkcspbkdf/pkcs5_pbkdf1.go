package pkcspbkdf

func PKCS5PBKDF1(hash func([]byte) []byte, salt, password []byte, r int, size int) (key []byte) {
	derived := make([]byte, len(password)+len(salt))
	copy(derived, password)
	copy(derived[len(password):], salt)

	for i := 0; i < r; i++ {
		derived = hash(derived)
	}

	return derived[:size]
}
