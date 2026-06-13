package dns

import (
	"strings"
	"testing"
)

func TestSuffixes(t *testing.T) {
	TLDs := []string{".no"}
	subdomains := []string{".google.com"}

	suffixAllowList, err := buildSuffixesSearch(TLDs, subdomains)
	if err != nil {
		t.Fatal(err)
	}

	if !suffixAllowList.MatchSuffix([]byte("foo.google.com")) {
		t.Errorf("fail")
	}

	if suffixAllowList.MatchSuffix([]byte(".google.com")) {
		t.Errorf("fail")
	}

	if suffixAllowList.MatchSuffix([]byte("google.com")) {
		t.Errorf("fail")
	}

	if suffixAllowList.MatchSuffix([]byte("")) {
		t.Errorf("fail")
	}
}

func TestDomain(t *testing.T) {
	domains := []string{"google.com"}

	domainAllowList, err := buildDomainSearch(domains)
	if err != nil {
		t.Fatal(err)
	}

	if !domainAllowList.MatchExact([]byte("google.com")) {
		t.Errorf("fail")
	}

	if domainAllowList.MatchExact([]byte("agoogle.com")) {
		t.Errorf("fail")
	}

	if domainAllowList.MatchExact([]byte("ooogle.com")) {
		t.Errorf("fail")
	}

	if domainAllowList.MatchExact([]byte("oogle.com")) {
		t.Errorf("fail")
	}

	if domainAllowList.MatchExact([]byte("")) {
		t.Errorf("fail")
	}
}

func TestDomainHasCorrectFormat(t *testing.T) {
	policy := Policy{
		blockPunycode: true,
		knownTLDs: map[string]struct{}{
			"com": {},
		},
	}

	err := policy.domainHasCorrectFormat("example.com")
	if err != nil {
		t.Fatal(err)
	}

	err = policy.domainHasCorrectFormat(".example.com")
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr := "unexpected leading '.'"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	err = policy.domainHasCorrectFormat("example.com.")
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "unexpected trailing '.'"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	err = policy.domainHasCorrectFormat("com")
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "domain is not at least two parts"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	sb := stringBuilderWith250Characters()
	sb.WriteString("bbbb")
	tooLong := sb.String()
	err = policy.domainHasCorrectFormat(tooLong)
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "domain is too long: 254"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	sb = stringBuilderWith250Characters()
	sb.WriteString("com")
	almostTooLong := sb.String()
	err = policy.domainHasCorrectFormat(almostTooLong)
	if err != nil {
		t.Fatal(err)
	}

	sb = &strings.Builder{}
	for i := 0; i < 64; i++ {
		sb.WriteString("a")
	}
	sb.WriteString(".com")
	tooLongLabel := sb.String()
	err = policy.domainHasCorrectFormat(tooLongLabel)
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "label is too long"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	sb = &strings.Builder{}
	for i := 0; i < 63; i++ {
		sb.WriteString("a")
	}
	sb.WriteString(".com")
	almostTooLongLabel := sb.String()
	err = policy.domainHasCorrectFormat(almostTooLongLabel)
	if err != nil {
		t.Fatal(err)
	}

	err = policy.domainHasCorrectFormat("_test.com")
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "illegal characters in label"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	err = policy.domainHasCorrectFormat("xn--test.com")
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "punycode present"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}

	err = policy.domainHasCorrectFormat("example.org")
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr = "not a valid TLD"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestCorrectCNAMEChain(t *testing.T) {
	var cnames = make(map[string]string)
	cnames["a.com"] = "b.com"
	cnames["b.com"] = "c.com"
	cnames["c.com"] = "d.com"
	cnames["d.com"] = "e.com"
	cnames["e.com"] = "f.com"
	cnames["f.com"] = "g.com"
	cnames["g.com"] = "h.com"
	cnames["h.com"] = "i.com"
	cnames["i.com"] = "j.com"
	cnames["j.com"] = "k.com"

	end := make(map[string]struct{})
	end["k.com"] = struct{}{}

	err := correctCNAMEChain(cnames, "a.com", end)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnrelatedCNAMERecords(t *testing.T) {
	var cnames = make(map[string]string)
	cnames["a.com"] = "b.com"
	cnames["b.com"] = "c.com"
	cnames["k.com"] = "l.com"

	end := make(map[string]struct{})
	end["c.com"] = struct{}{}

	err := correctCNAMEChain(cnames, "a.com", end)
	if err == nil {
		t.Fatalf("should fail")
	}

	expectedErr := "incomplete CNAME chain"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestTooLongCNAMEChain(t *testing.T) {
	var cnames = make(map[string]string)
	cnames["a.com"] = "b.com"
	cnames["b.com"] = "c.com"
	cnames["c.com"] = "d.com"
	cnames["d.com"] = "e.com"
	cnames["e.com"] = "f.com"
	cnames["f.com"] = "g.com"
	cnames["g.com"] = "h.com"
	cnames["h.com"] = "i.com"
	cnames["i.com"] = "j.com"
	cnames["j.com"] = "k.com"
	cnames["k.com"] = "l.com"

	end := make(map[string]struct{})
	end["l.com"] = struct{}{}

	err := correctCNAMEChain(cnames, "a.com", end)
	if err == nil {
		t.Fatalf("should fail")
	}

	expectedErr := "too many CNAME records"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}
}

func TestLoopInCNAMEChain(t *testing.T) {
	var cnames = make(map[string]string)
	cnames["a.com"] = "b.com"
	cnames["b.com"] = "a.com"
	cnames["d.com"] = "e.com"

	end := make(map[string]struct{})
	end["b.com"] = struct{}{}

	err := correctCNAMEChain(cnames, "a.com", end)
	if err == nil {
		t.Fatalf("should fail")
	}
	expectedErr := "loop in CNAME chain"
	if err.Error() != expectedErr {
		t.Fatalf("expected '%s', got '%s'", expectedErr, err.Error())
	}
}
