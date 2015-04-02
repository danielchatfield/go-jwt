package jwt

import (
	"crypto"
	"crypto/hmac"
)

// SigningAlgorithmHMAC represents an HMAC signing algorithm
type SigningAlgorithmHMAC struct {
	name string
	hash crypto.Hash
}

// Instances of supported signing algorithms
var (
	SigningAlgorithmHS256 = &SigningAlgorithmHMAC{"HS256", crypto.SHA256}
	SigningAlgorithmHS384 = &SigningAlgorithmHMAC{"HS384", crypto.SHA384}
	SigningAlgorithmHS512 = &SigningAlgorithmHMAC{"HS512", crypto.SHA512}
)

// Name returns the name of the algorithm as specified in JSON Web Algorithms
func (alg *SigningAlgorithmHMAC) Name() string {
	return alg.name
}

func (alg *SigningAlgorithmHMAC) sign(payload string, key interface{}) ([]byte, error) {
	var byteArray []byte

	switch k := key.(type) {
	case []byte:
		byteArray = k
	case string:
		byteArray = []byte(k)
	default:
		return nil, ErrInvalidKey
	}

	// byteArray now holds the key

	// hmac.New expects a function to return the hash.Hash so we need to get a
	// function to do that
	hashFunc, err := newHashFunc(alg.hash)

	if err != nil {
		return nil, err
	}

	hasher := hmac.New(hashFunc, byteArray)
	hasher.Write([]byte(payload))

	return hasher.Sum(nil), nil
}

// Sign takes a string payload and either a byte array key or a string key and
// returns the signature as a string or an error
func (alg *SigningAlgorithmHMAC) Sign(payload string, key interface{}) (string, error) {
	var (
		sigBytes []byte
		err      error
	)

	if sigBytes, err = alg.sign(payload, key); err == nil {
		return encode(sigBytes), nil
	}

	return "", err
}

// Verify calculates the signature and checks that it matches.
func (alg *SigningAlgorithmHMAC) Verify(payload string, signature string, key interface{}) error {
	var (
		checkSig []byte
		origSig  []byte
		err      error
	)

	if checkSig, err = alg.sign(payload, key); err != nil {
		return err
	}

	if origSig, err = decode(signature); err != nil {
		return err
	}

	// we have generated the signature, lets compare them
	if hmac.Equal(checkSig, origSig) {
		return nil
	}

	return ErrBadSignature
}
