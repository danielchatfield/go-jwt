package jwt

import (
	"encoding/base64"
	"strings"
)

func encode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func decode(data string) ([]byte, error) {
	// add padding that was removed by encoder
	if l := len(data) % 4; l > 0 {
		data += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(data)
}
