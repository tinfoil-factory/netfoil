package dns

import (
	"encoding/base64"
	"testing"
)

func TestECHConfig(t *testing.T) {
	echString := "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"

	ech, err := base64.StdEncoding.DecodeString(echString)
	if err != nil {
		t.Fatal(err)
	}

	configs, err := UnmarshalECHConfig(ech)
	if err != nil {
		t.Fatal(err)
	}

	r, err := MarshalECHConfig(configs)
	if err != nil {
		t.Fatal(err)
	}

	res := base64.StdEncoding.EncodeToString(r)
	if echString != res {
		t.Errorf("Marshal/Unmarshal mismatch: got '%s', want '%s'", res, echString)
	}
}
