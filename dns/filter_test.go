package dns

import (
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
