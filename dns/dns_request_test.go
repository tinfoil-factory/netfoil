package dns

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestRequest(t *testing.T) {
	h := "JvwBAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ=="
	r, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}

	request, err := UnmarshalRequest(r)
	if err != nil {
		t.Fatal(err)
	}

	if request.Questions[0].Name != "google.com" {
		t.Errorf("expected question %s, got %s", "google.com", request.Questions[0].Name)
	}

	marshalled, err := MarshalRequest(request)

	if !bytes.Equal(marshalled, r) {
		t.Errorf("expected marshalled %s, got %s", hex.EncodeToString(r), hex.EncodeToString(marshalled))
	}
}
