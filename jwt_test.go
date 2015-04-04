package jwt

import (
	"testing"
	"time"
)

var testKey = "super-secret-key"
var testToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0ZXN0IjoidGVzdCJ9.wrGG2c43twEDYjN63iRLE3CEXw6AI2E7-iRQFWkSvzI"

func TestNewToken(t *testing.T) {
	if tok, ok := NewToken(HMAC).(*token); ok {
		if tok.header["typ"] != "JWT" {
			t.Error("typ field in token header incorrect")
		}

		if tok.header["alg"] != HMAC.Name() {
			t.Error("alg field in token header incorrect")
		}
	} else {
		t.Error("NewToken did not return value of type 'token'")
	}
}

func TestClaimString(t *testing.T) {
	tok := NewToken(HMAC)

	tok.SetClaim("test", "result")
	if res, ok := tok.Claim("test").(string); ok {
		if res != "result" {
			t.Errorf("String claim not set correctly, expected %v but got %v", "result", res)
		}
	} else {
		t.Errorf("Type assertion on string retrieved from claims failed")
	}
}

func TestEncode(t *testing.T) {
	tok := NewToken(HMAC)

	tok.SetClaim("test", "test")

	encoded, err := tok.Encode(testKey)

	if err != nil {
		t.Errorf("An error occured encoding the token: %v", err)
	}

	if encoded != testToken {
		t.Errorf("Token encoding error, expecting:\n%v\n\ngot:\n%v", testToken, encoded)
	}
}

func TestParseToken(t *testing.T) {
	tok, err := ParseToken(testToken, HMAC, testKey)

	if err != nil {
		t.Errorf("Error occured parsing the token: %v", err)
	}

	if test, ok := tok.Claim("test").(string); ok {
		if test != "test" {
			t.Errorf("test claim not correct in parsed token")
		}
	} else {
		t.Errorf("test claim not recovered from parsed token")
	}
}

func expectError(t *testing.T, tok Token, e ValidationError) {
	encoded, err := tok.Encode(testKey)

	if err != nil {
		t.Errorf("Error whilst encoding token: %v", err)
	}

	_, err = ParseToken(encoded, HMAC, testKey)

	if err == nil {
		t.Errorf("Expected error but didn't get it")
	} else {
		if err.(ValidationError) != e {
			t.Errorf("Errors don't match expectation")
		}
	}
}

func TestTokenExpired(t *testing.T) {
	tok := NewToken(HMAC)

	tok.SetClaim("exp", time.Now().Unix()-100)

	expectError(t, tok, ExpiredError)
}
