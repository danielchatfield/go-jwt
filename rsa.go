package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// SigningAlgorithmRSA represents an RSA signing algorithm
type SigningAlgorithmRSA struct {
	name string
	hash crypto.Hash
}

// Instances of support hashing algs
var (
	SigningAlgorithmRS256 = &SigningAlgorithmRSA{"RS256", crypto.SHA256}
	SigningAlgorithmRS384 = &SigningAlgorithmRSA{"RS384", crypto.SHA384}
	SigningAlgorithmRS512 = &SigningAlgorithmRSA{"RS512", crypto.SHA512}
)

// Name returns the name of the algorithm as specified in JSON Web Algorithms
func (alg *SigningAlgorithmRSA) Name() string {
	return alg.name
}

func (alg *SigningAlgorithmRSA) sign(payload string, key interface{}) ([]byte, error) {
	var (
		rsaKey *rsa.PrivateKey
		err    error
	)

	switch k := key.(type) {
	case string:
		if rsaKey, err = ParseRSAPrivateKeyFromPEM([]byte(k)); err != nil {
			return nil, err
		}
	case []byte:
		if rsaKey, err = ParseRSAPrivateKeyFromPEM([]byte(k)); err != nil {
			return nil, err
		}
	case *rsa.PrivateKey:
		rsaKey = k
	default:
		return nil, ErrInvalidKey
	}

	hashFunc, err := newHashFunc(alg.hash)

	if err != nil {
		return nil, err
	}

	hasher := hashFunc()
	hasher.Write([]byte(payload))

	// Sign the string and return the encoded bytes
	if sigBytes, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, alg.hash, hasher.Sum(nil)); err == nil {
		return sigBytes, nil
	}

	return nil, err
}

// Sign takes a string payload and a key as either an rsa.PrivateKey or a string or
// byte array containing a PEM encoded key.
// Either returns the signature as a string or an error.
func (alg *SigningAlgorithmRSA) Sign(payload string, key interface{}) (string, error) {
	var (
		sigBytes []byte
		err      error
	)

	if sigBytes, err = alg.sign(payload, key); err == nil {
		return encode(sigBytes), nil
	}

	return "", err
}

// Verify checks that the signature is valid
func (alg *SigningAlgorithmRSA) Verify(payload string, signature string, key interface{}) error {
	var (
		rsaKey   *rsa.PublicKey
		sigBytes []byte
		err      error
	)

	// decode the signature
	if sigBytes, err = decode(signature); err != nil {
		return err
	}

	switch k := key.(type) {
	case string:
		if rsaKey, err = ParseRSAPublicKeyFromPEM([]byte(k)); err != nil {
			return err
		}
	case []byte:
		if rsaKey, err = ParseRSAPublicKeyFromPEM([]byte(k)); err != nil {
			return err
		}
	case *rsa.PublicKey:
		rsaKey = k
	default:
		return ErrInvalidKey
	}

	hashFunc, err := newHashFunc(alg.hash)

	if err != nil {
		return err
	}

	hasher := hashFunc()
	hasher.Write([]byte(payload))

	return rsa.VerifyPKCS1v15(rsaKey, alg.hash, hasher.Sum(nil), sigBytes)
}

// Errors relating to parsing PEMs
var (
	ErrKeyMustBePEMEncoded = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	ErrNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
)

// ParseRSAPrivateKeyFromPEM decodes a PEM encoded PKCS1 or PKCS8 private key
func ParseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}

// ParseRSAPublicKeyFromPEM decodes a  PEM encoded PKCS1 or PKCS8 public key
func ParseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, ErrKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, ErrNotRSAPrivateKey
	}

	return pkey, nil
}
