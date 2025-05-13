package dns

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseConfig(t *testing.T) {
	s := `# comment

DoHURL=https://example.com/dns-query
DoHIPs=0.0.0.0
MinTTL=60
MaxTTL=4294967295
DenyPunycode=true
RemoveECH=false`

	reader := strings.NewReader(s)
	scanner := bufio.NewScanner(reader)

	config, err := parseConfig(scanner)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if config.DoHURL != "https://example.com/dns-query" {
		t.Errorf("wrong DoHURL")
	}

	if len(config.DoHIPs) != 1 || config.DoHIPs[0] != "0.0.0.0" {
		t.Errorf("wrong DoHIPs")
	}

	if config.MinTTL != 60 {
		t.Errorf("Wrong MinTTL")
	}

	if config.MaxTTL != 4294967295 {
		t.Errorf("wrong MaxTTL")
	}

	if config.DenyPunycode != true {
		t.Errorf("AllowPunycode should be false")
	}

	if config.RemoveECH != false {
		t.Errorf("RemoveECH should be true")
	}
}
