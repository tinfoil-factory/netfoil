package dns

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestResponse(t *testing.T) {
	h := "H0CBgAABAAEAAAAABmdvb2dsZQNjb20AAAEAAcAMAAEAAQAAASoABI76sk4="
	r, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}

	response, err := UnmarshalResponse(r)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%t\n", response.Flags.RD)
}
