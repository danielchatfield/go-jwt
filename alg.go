package jwt

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// SigningAlgorithm represents a signing algorithm
type SigningAlgorithm interface {
	Name() string
	Sign(payload string, key interface{}) ([]byte, error)
	Verify(payload string, signature string, key interface{}) error
}

func newHashFunc(method crypto.Hash) (h func() hash.Hash, err error) {
	switch method {
	case crypto.SHA256:
		h = sha256.New
	case crypto.SHA384:
		h = sha512.New384
	case crypto.SHA512:
		h = sha512.New
	default:
		if !method.Available() {
			return nil, ErrHashUnavailable
		}

		// hash is available
		h = method.New
	}
	return
}
