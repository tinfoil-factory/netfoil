package dns

import (
	"bufio"
	"log/slog"
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
RemoveECH=false
LogAllowed=false
LogDenied=true
LogLevel=debug`

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
		t.Errorf("DenyPunycode should be true")
	}

	if config.RemoveECH != false {
		t.Errorf("RemoveECH should be false")
	}

	if config.LogAllowed != false {
		t.Errorf("LogAllowed should be false")
	}

	if config.LogDenied != true {
		t.Errorf("LogDenied should be true")
	}

	if config.LogLevel != slog.LevelDebug {
		t.Errorf("LogLevel should be debug")
	}
}

func TestGetBool(t *testing.T) {
	s := `DoHURL=https://example.com/dns-query
DoHIPs=0.0.0.0
DenyPunycode=true
PinResponseDomain=true
LogAllowed=false`

	reader := strings.NewReader(s)
	scanner := bufio.NewScanner(reader)

	config, err := parseConfig(scanner)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if config.DenyPunycode != true {
		t.Errorf("DenyPunycode should be true")
	}

	if config.RemoveECH != false {
		t.Errorf("RemoveECH should be false")
	}

	if config.PinResponseDomain != true {
		t.Errorf("PinResponseDomain should be true")
	}

	if config.LogAllowed != false {
		t.Errorf("LogAllowed should be false")
	}

	if config.LogDenied != true {
		t.Errorf("LogDenied should be true")
	}
}

func TestGetLogLevelDefault(t *testing.T) {
	s := `DoHURL=https://example.com/dns-query
DoHIPs=0.0.0.0`

	reader := strings.NewReader(s)
	scanner := bufio.NewScanner(reader)

	config, err := parseConfig(scanner)
	if err != nil {
		t.Fatalf("failed to parse config: %v", err)
	}

	if config.LogLevel != slog.LevelInfo {
		t.Errorf("LogLevel should be info")
	}
}
