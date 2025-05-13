package suffixtrie

import "testing"

func TestExact(t *testing.T) {
	s := Node{}

	err := s.InsertMultiple([]string{".com", ".org"})
	if err != nil {
		t.Fatal(err)
	}

	if s.MatchExact([]byte("")) {
		t.Errorf("should not match")
	}

	if !s.MatchExact([]byte(".com")) {
		t.Errorf("should match")
	}

	if !s.MatchExact([]byte(".org")) {
		t.Errorf("should match")
	}

	if s.MatchExact([]byte("example.com")) {
		t.Errorf("should not match")
	}

	if s.MatchExact([]byte("example.org")) {
		t.Errorf("should not match")
	}

	if s.MatchExact([]byte("om")) {
		t.Errorf("should not match")
	}

	if s.MatchExact([]byte("rg")) {
		t.Errorf("should not match")
	}
}

func TestSuffix(t *testing.T) {
	s := Node{}

	err := s.InsertMultiple([]string{".com", ".org"})
	if err != nil {
		t.Fatal(err)
	}

	if !s.MatchSuffix([]byte("")) {
		t.Errorf("should match empty string")
	}

	if s.MatchSuffix([]byte("com")) {
		t.Errorf("should not match")
	}

	if s.MatchSuffix([]byte("org")) {
		t.Errorf("should not match")
	}

	if !s.MatchSuffix([]byte(".com")) {
		t.Errorf("should match")
	}

	if !s.MatchSuffix([]byte(".org")) {
		t.Errorf("should match")
	}

	if !s.MatchSuffix([]byte("example.com")) {
		t.Errorf("should match")
	}

	if !s.MatchSuffix([]byte("example.org")) {
		t.Errorf("should match")
	}

	if s.MatchSuffix([]byte("om")) {
		t.Errorf("should not match")
	}

	if s.MatchSuffix([]byte("rg")) {
		t.Errorf("should not match")
	}
}
