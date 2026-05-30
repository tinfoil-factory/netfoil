package dns

import "testing"

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
		marshalled := MarshalFlags(&test)
		unmarshalled := UnmarshalFlags(marshalled)

		if !flagEquals(test, *unmarshalled) {
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
