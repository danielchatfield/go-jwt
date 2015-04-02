package jwt

import (
	"errors"
	"time"
)

// TimeFunc is used to get the current time when validating the "exp" claim
var TimeFunc = time.Now

var (
	ErrInvalidKey      = errors.New("The key is invalid or of invalid type")
	ErrHashUnavailable = errors.New("The hashing algorithm is not available")
	ErrBadSignature    = errors.New("The signature doesn't match")
)

type Token interface {
	Valid() bool
}

type token struct {
	raw       string
	algorithm SigningAlgorithm
	header    map[string]interface{}
	claims    map[string]interface{}
	signature string
	valid     bool
}

// NewToken creates a new token with the specified SigningAlgorithm
func NewToken(alg SigningAlgorithm) Token {
	return &token{
		header: map[string]interface{}{
			"typ": "JWT",
			"alg": alg.Name(),
		},
		claims:    make(map[string]interface{}),
		algorithm: alg,
	}
}

func (t *token) Valid() bool {
	return t.valid
}
