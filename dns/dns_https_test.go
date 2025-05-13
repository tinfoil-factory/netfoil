package dns

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHTTPS(t *testing.T) {
	r := "\\\\# 136 00 01 00 00 01 00 06 02 68 33 02 68 32 00 04 00 08 68 15 20 27 ac 43 b6 c4 00 05 00 47 00 45 fe 0d 00 41 c9 00 20 00 20 14 c9 87 0d 98 3a 50 bf 4a 82 55 d8 aa 7b 0a f2 fa 3d 60 8f 07 ee 1f c8 d5 12 52 e9 75 9a 8a 5e 00 04 00 01 00 01 00 12 63 6c 6f 75 64 66 6c 61 72 65 2d 65 63 68 2e 63 6f 6d 00 00 00 06 00 20 26 06 47 00 30 31 00 00 00 00 00 00 68 15 20 27 26 06 47 00 30 34 00 00 00 00 00 00 ac 43 b6 c4"

	originalData, err := decodeCloudflareRecord(r)
	if err != nil {
		t.Fatal(err)
	}

	record, err := unmarshalHTTPSRecord(originalData)
	if err != nil {
		t.Fatal(err)
	}

	if record.TargetName != "" {
		t.Fatal("target name should be empty")
	}

	if record.ALPN[0] == "h2" {
		t.Fatalf("alpn does not match, expected 'h2', got %s", record.ALPN[0])
	}

	if record.ALPN[1] == "h3" {
		t.Fatalf("alpn does not match, expected 'h2', got %s", record.ALPN[0])
	}

	expectedIPv4 := "104.21.32.39"
	actualIPv4 := record.IPv4Hint[0].String()
	if actualIPv4 != expectedIPv4 {
		t.Fatalf("ip does not match, expected '%s', got %s", expectedIPv4, actualIPv4)
	}

	expectedIPv4 = "172.67.182.196"
	actualIPv4 = record.IPv4Hint[1].String()
	if actualIPv4 != expectedIPv4 {
		t.Fatalf("ip does not match, expected '%s', got %s", expectedIPv4, actualIPv4)
	}

	expectedIPv6 := "2606:4700:3031::6815:2027"
	actualIPv6 := record.IPv6Hint[0].String()
	if actualIPv6 != expectedIPv6 {
		t.Fatalf("ip does not match, expected '%s', got %s", expectedIPv6, actualIPv6)
	}

	expectedIPv6 = "2606:4700:3034::ac43:b6c4"
	actualIPv6 = record.IPv6Hint[1].String()
	if actualIPv6 != expectedIPv6 {
		t.Fatalf("ip does not match, expected '%s', got %s", expectedIPv6, actualIPv6)
	}

	marshalledData, err := marshalHTTPSRecord(record)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(marshalledData, originalData) {
		t.Errorf("got %q, want %q", hex.EncodeToString(marshalledData), hex.EncodeToString(originalData))
	}

	r2 := encodeCloudflareRecord(marshalledData)
	if r != r2 {
		t.Errorf("got %q, want %q", r2, r)
	}
}
