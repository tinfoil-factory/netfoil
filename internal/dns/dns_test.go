package dns

import (
	"bytes"
	"strings"
	"testing"
)

func TestFlagsAllSet(t *testing.T) {
	tests := []Flags{
		{QR: true},
		{OPCODE: 1},
		{OPCODE: 15},
		{AA: true},
		{TC: true},
		{RD: true},
		{RA: true},
		{Z: true},
		{AD: true},
		{CD: true},
		{RCODE: 1},
		{RCODE: 15},
		{
			QR:     false,
			OPCODE: 0,
			AA:     false,
			TC:     false,
			RD:     false,
			RA:     false,
			Z:      false,
			AD:     false,
			CD:     false,
			RCODE:  0,
		},
		{
			QR:     true,
			OPCODE: 15,
			AA:     true,
			TC:     true,
			RD:     true,
			RA:     true,
			Z:      true,
			AD:     true,
			CD:     true,
			RCODE:  15,
		},
	}

	for _, test := range tests {
		marshalled := MarshalFlags(test)
		unmarshalled := UnmarshalFlags(marshalled)

		if !flagEquals(test, unmarshalled) {
			t.Errorf("flag marshal/unmarshal failed for %v", test)
		}
	}

}

func flagEquals(a Flags, b Flags) bool {
	if a.QR != b.QR {
		return false
	}

	if a.OPCODE != b.OPCODE {
		return false
	}

	if a.AA != b.AA {
		return false
	}

	if a.TC != b.TC {
		return false
	}

	if a.RD != b.RD {
		return false
	}

	if a.RA != b.RA {
		return false
	}

	if a.Z != b.Z {
		return false
	}

	if a.AD != b.AD {
		return false
	}

	if a.CD != b.CD {
		return false
	}

	if a.RCODE != b.RCODE {
		return false
	}

	return true
}

func TestName(t *testing.T) {
	testDomains := []string{
		".",
		"com.",
		"example.com.",
	}

	for _, testDomain := range testDomains {
		buffer := &bytes.Buffer{}
		err := writeDomain(buffer, testDomain)
		if err != nil {
			t.Fatal(err)
		}

		domain, err := readDomain(buffer.Bytes(), buffer, true)
		if err != nil {
			t.Fatal(err)
		}

		if domain != testDomain {
			t.Fatalf("expected '%s', got '%s'", testDomain, domain)
		}
	}
}

func TestTooLongName(t *testing.T) {
	buffer := &bytes.Buffer{}

	sb := stringBuilderWith250Characters()
	sb.WriteString("bbbb.")
	tooLong := sb.String()

	if len(tooLong) != 255 {
		t.Fatalf("expected name length 255, got %d", len(tooLong))
	}

	err := writeDomain(buffer, tooLong)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readDomain(buffer.Bytes(), buffer, true)
	if err == nil {
		t.Fatal("expected error, got none")
	}

	expected := "domain name too long"
	if err.Error() != expected {
		t.Fatalf("expected error '%s', got '%s'", expected, err.Error())
	}
}

func TestAlmostTooLongName(t *testing.T) {
	buffer := &bytes.Buffer{}

	sb := stringBuilderWith250Characters()
	sb.WriteString("bbb.")
	almostTooLong := sb.String()

	if len(almostTooLong) != 254 {
		t.Fatalf("expected name length 254, got %d", len(almostTooLong))
	}

	err := writeDomain(buffer, almostTooLong)
	if err != nil {
		t.Fatal(err)
	}

	_, err = readDomain(buffer.Bytes(), buffer, true)
	if err != nil {
		t.Fatal(err)
	}

}

func stringBuilderWith250Characters() *strings.Builder {
	sb := strings.Builder{}
	for j := 0; j < 5; j++ {
		for i := 0; i < 49; i++ {
			sb.WriteString("a")
		}
		sb.WriteString(".")
	}

	return &sb
}
