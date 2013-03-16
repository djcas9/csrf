package csrf

import (
  "encoding/base64"
	"testing"
)

var (
	action = string("POST /form")
	id     = string("13243434")
)

func TestToken(t *testing.T) {
	Key = Rand16()
	s := newToken(action, id)
	if !Valid(s, action, id) {
		t.Error("Expected token to be valid.")
	}
	action = string("POST /diferentform")
	if Valid(s, action, id) {
		t.Error("Expected token to be invalid diferen actionID")
	}
	id = string("9894848493")
	if Valid(s, action, id) {
		t.Error("Expected token to be invalid diferen user ID")
	}
	d := newToken(action, id)
	Key = Rand16()
	if Valid(d, action, id) {
		t.Error("Expected token to be invalid diferen hmac key")
	}

}

func TestMalformed(t *testing.T) {
	a := string(Rand16())
	if Valid(a, action, id) {
		t.Errorf("Expected generated token to be invalid, malformed data")
	}
	b := base64.URLEncoding.EncodeToString([]byte("foobarzap1234567804343434"))
	if Valid(b, action, id) {
		t.Errorf("Expected generated token to be invalid, malformed data")
	}
}
