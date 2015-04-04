package jwt

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// TimeFunc is used to get the current time when validating the "exp" claim
var TimeFunc = time.Now

var (
	ErrInvalidKey      = errors.New("The key is invalid or of invalid type")
	ErrHashUnavailable = errors.New("The hashing algorithm is not available")
	ErrBadSignature    = errors.New("The signature doesn't match")
	ErrTokenMalformed  = errors.New("The token is malformed")
)

const (
	BadSignatureError ValidationError = 1 << iota
	ExpiredError
	NotYetValidError
)

type ValidationError uint32

func (e ValidationError) Error() string {
	return "the token is invalid"
}

type Token interface {
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

func ParseToken(tokenString string, alg SigningAlgorithm, key interface{}) (Token, error) {
	segments := strings.Split(tokenString, ".")

	if len(segments) != 3 {
		return nil, ErrTokenMalformed
	}

	t := &token{
		raw: tokenString,
	}

	var (
		headerBytes []byte
		err         error
	)

	if headerBytes, err = decode(segments[0]); err != nil {
		return t, ErrTokenMalformed
	}

	if err = json.Unmarshal(headerBytes, &t.header); err != nil {
		return t, ErrTokenMalformed
	}

	var claimBytes []byte
	if claimBytes, err = decode(segments[1]); err != nil {
		return t, ErrTokenMalformed
	}

	if err = json.Unmarshal(claimBytes, &t.claims); err != nil {
		return t, ErrTokenMalformed
	}

	var errs ValidationError

	// check sig
	if err = alg.Verify(strings.Join(segments[0:2], "."), segments[2], key); err != nil {
		errs |= BadSignatureError
	}

	// check exp
	now := TimeFunc().Unix()

	if exp, ok := t.claims["exp"].(float64); ok {
		if now > int64(exp) {
			errs |= ExpiredError
		}
	}

	if nbf, ok := t.claims["nbf"].(float64); ok {
		if now < int64(nbf) {
			errs |= NotYetValidError
		}
	}

	if errs == 0 {
		return t, nil
	}

	return t, errs

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
