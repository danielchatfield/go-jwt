package jwt

import (
	"strings"
	"testing"
)

var (
	hs256Test = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	hs384Test = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0." +
		"KWZEuOD5lbBxZ34g7F-SlVLAQ_r5KApWNWlZIIMyQVz5Zs58a7XdNzj5_0EcNoOy"

	hs512Test = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9." +
		"eyJleHAiOjEuMzAwODE5MzhlKzA5LCJodHRwOi8vZXhhbXBsZS5jb20vaXNfcm9vdCI6dHJ1ZSwiaXNzIjoiam9lIn0." +
		"CN7YijRX6Aw1n2jyI2Id1w90ja-DEMYiWixhYCyHnrZ1VfJRaFQz1bEbjjA5Fn4CLYaUG432dEYmSbS4Saokmw"

	hmacInvalidTest = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXo"

	hmacStringKeyTest = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0." +
		"OLvs36KmqB9cmsUrMpUutfhV52_iSz4bQMYJjkI_TLQ"
)

var hmacTestKey = []byte{
	0x03, 0x23, 0x35, 0x4b, 0x2b, 0x0f, 0xa5, 0xbc,
	0x83, 0x7e, 0x06, 0x65, 0x77, 0x7b, 0xa6, 0x8f,
	0x5a, 0xb3, 0x28, 0xe6, 0xf0, 0x54, 0xc9, 0x28,
	0xa9, 0x0f, 0x84, 0xb2, 0xd2, 0x50, 0x2e, 0xbf,
	0xd3, 0xfb, 0x5a, 0x92, 0xd2, 0x06, 0x47, 0xef,
	0x96, 0x8a, 0xb4, 0xc3, 0x77, 0x62, 0x3d, 0x22,
	0x3d, 0x2e, 0x21, 0x72, 0x05, 0x2e, 0x4f, 0x08,
	0xc0, 0xcd, 0x9a, 0xf5, 0x67, 0xd0, 0x80, 0xa3,
}

func testHMACSign(t *testing.T, token string, alg *SigningAlgorithmHMAC) {
	segments := strings.Split(token, ".")

	sig, err := alg.Sign(
		strings.Join(segments[0:2], "."),
		hmacTestKey,
	)

	if err != nil {
		t.Errorf("[%v] Error while signing token: %v", alg.Name(), err)
	}

	if sig != segments[2] {
		t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", alg.Name(), sig, segments[2])
	}
}

func testHMACVerify(t *testing.T, token string, alg *SigningAlgorithmHMAC) {
	segments := strings.Split(token, ".")

	err := alg.Verify(
		strings.Join(segments[0:2], "."),
		segments[2],
		hmacTestKey,
	)

	if err != nil {
		t.Errorf("[%v] Error while verifying signature: %v", alg.Name(), err)
	}
}

func TestHS256Sign(t *testing.T) {
	testHMACSign(t, hs256Test, SigningAlgorithmHS256)
}

func TestHS256Verify(t *testing.T) {
	testHMACVerify(t, hs256Test, SigningAlgorithmHS256)
}

func TestHS384Sign(t *testing.T) {
	testHMACSign(t, hs384Test, SigningAlgorithmHS384)
}

func TestHS384Verify(t *testing.T) {
	testHMACVerify(t, hs384Test, SigningAlgorithmHS384)
}

func TestHS512Sign(t *testing.T) {
	testHMACSign(t, hs512Test, SigningAlgorithmHS512)
}

func TestHS512Verify(t *testing.T) {
	testHMACVerify(t, hs512Test, SigningAlgorithmHS512)
}

func TestInvalidSignature(t *testing.T) {
	segments := strings.Split(hmacInvalidTest, ".")

	err := SigningAlgorithmHS256.Verify(
		strings.Join(segments[0:2], "."),
		segments[2],
		hmacTestKey,
	)

	if err == nil {
		t.Errorf("[HS256] Invalid signature passed verification")
	}
}

func TestStringKey(t *testing.T) {
	segments := strings.Split(hmacStringKeyTest, ".")

	sig, err := SigningAlgorithmHS256.Sign(
		strings.Join(segments[0:2], "."),
		"secret",
	)

	if err != nil {
		t.Errorf("[%v] Error while signing token: %v", "HS256", err)
	}

	if sig != segments[2] {
		t.Errorf("[%v] Incorrect signature.\nwas:\n%v\nexpecting:\n%v", "HS256", sig, segments[2])
	}
}
