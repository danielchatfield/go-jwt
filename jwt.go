package jwt

import (
	"encoding/json"
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
	Encode(key interface{}) (payload string, err error)
	Claim(string) interface{}
	SetClaim(string, interface{})
}

type token struct {
	raw       string
	alg       SigningAlgorithm
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
		claims: make(map[string]interface{}),
		alg:    alg,
	}
}

func (t *token) Valid() bool {
	return t.valid
}

func (t *token) Claim(claim string) interface{} {
	return t.claims[claim]
}

func (t *token) SetClaim(claim string, v interface{}) {
	t.claims[claim] = v
}

func (t *token) Encode(key interface{}) (payload string, err error) {
	var sig string

	if payload, err = t.payload(); err != nil {
		return
	}

	if sig, err = t.alg.Sign(payload, key); err != nil {
		return
	}

	payload += "." + sig

	return
}

func (t *token) payload() (payload string, err error) {
	var jsonValue []byte

	// lets do the header
	if jsonValue, err = json.Marshal(t.header); err != nil {
		return
	}

	payload = encode(jsonValue)

	if jsonValue, err = json.Marshal(t.claims); err != nil {
		return
	}

	payload += "." + encode(jsonValue)

	return
}
