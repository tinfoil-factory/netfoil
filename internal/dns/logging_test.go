package dns

import (
	"testing"
)

func TestEscapeNonStandard(t *testing.T) {
	t1 := "-_a.b.YZ.10"
	r1 := escapeNonStandard(t1)
	expected := "-_a.b.YZ.10"
	if r1 != expected {
		t.Errorf("expected %s, got %s", expected, r1)
	}

	t2 := "a\nb"
	r2 := escapeNonStandard(t2)
	expected = "a\\010b"
	if r2 != expected {
		t.Errorf("expected %s, got %s", expected, r2)
	}

	t3 := "\n#$"
	r3 := escapeNonStandard(t3)
	expected = "\\010\\035\\036"
	if r3 != expected {
		t.Errorf("expected %s, got %s", expected, r3)
	}
}
