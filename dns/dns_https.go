package dns

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// https://datatracker.ietf.org/doc/html/rfc9460/

func decodeCloudflareRecord(data string) ([]byte, error) {
	r := data[4:]

	parts := strings.Split(r, " ")
	h := strings.Join(parts[1:], "")
	a, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}

	l, err := strconv.Atoi(parts[0])

	if len(a) != l {
		return nil, fmt.Errorf("invalid answer length: %d", len(a))
	}

	return a, nil
}

func encodeCloudflareRecord(data []byte) string {
	sb := strings.Builder{}

	sb.WriteString("\\\\# ")
	sb.WriteString(strconv.Itoa(len(data)))

	h := hex.EncodeToString(data)

	for i := 0; i < len(h)/2; i++ {
		sb.WriteByte(' ')
		sb.WriteString(h[2*i : 2*i+2])
	}

	return sb.String()
}

// https://datatracker.ietf.org/doc/html/rfc9460/#section-14.3.2
const (
	alpn uint16 = 1

	// TODO support
	noDefaultALPN uint16 = 2

	// TODO support
	port     uint16 = 3
	ipv4Hint uint16 = 4
	ech      uint16 = 5
	ipv6Hint uint16 = 6
)

type HTTPSRecord struct {
	Priority   uint16
	TargetName string
	ALPN       []string
	IPv4Hint   []net.IP
	ECH        []ECHConfig
	IPv6Hint   []net.IP
}

func marshalHTTPSRecord(record *HTTPSRecord) ([]byte, error) {
	var responseBuffer [1024]byte
	rp := bytes.NewBuffer(responseBuffer[:])
	rp.Reset()

	err := binary.Write(rp, binary.BigEndian, record.Priority)
	if err != nil {
		return nil, err
	}

	err = writeDomain(rp, record.TargetName)
	if err != nil {
		return nil, err
	}

	if len(record.ALPN) > 0 {
		err := binary.Write(rp, binary.BigEndian, alpn)
		if err != nil {
			return nil, err
		}

		size := uint16(0)
		for _, v := range record.ALPN {
			size += uint16(len(v))
		}
		size += uint16(len(record.ALPN))

		err = binary.Write(rp, binary.BigEndian, size)
		if err != nil {
			return nil, err
		}

		for _, v := range record.ALPN {
			err = writeArray8(rp, []byte(v))
			if err != nil {
				return nil, err
			}
		}
	}

	if len(record.IPv4Hint) > 0 {
		err = binary.Write(rp, binary.BigEndian, ipv4Hint)
		if err != nil {
			return nil, err
		}

		size := uint16(4 * len(record.IPv4Hint))
		err = binary.Write(rp, binary.BigEndian, size)
		if err != nil {
			return nil, err
		}

		for _, v := range record.IPv4Hint {
			l, err := rp.Write(v.To4())
			if err != nil {
				return nil, err
			}

			if l != 4 {
				return nil, fmt.Errorf("error writing IPv4: %d", l)
			}
		}
	}

	if len(record.ECH) > 0 {
		echData, err := MarshalECHConfig(record.ECH)
		if err != nil {
			return nil, err
		}

		err = binary.Write(rp, binary.BigEndian, ech)
		if err != nil {
			return nil, err
		}

		size := uint16(len(echData))
		err = binary.Write(rp, binary.BigEndian, size)
		if err != nil {
			return nil, err
		}

		l, err := rp.Write(echData)
		if err != nil {
			return nil, err
		}

		if l != len(echData) {
			return nil, fmt.Errorf("error writing ech: %d", l)
		}
	}

	if len(record.IPv6Hint) > 0 {
		err = binary.Write(rp, binary.BigEndian, ipv6Hint)
		if err != nil {
			return nil, err
		}

		size := uint16(16 * len(record.IPv6Hint))
		err = binary.Write(rp, binary.BigEndian, size)
		if err != nil {
			return nil, err
		}

		for _, v := range record.IPv6Hint {
			l, err := rp.Write(v)
			if err != nil {
				return nil, err
			}

			if l != 16 {
				return nil, fmt.Errorf("error writing IPv6: %d", l)
			}
		}
	}

	return rp.Bytes(), nil
}

func unmarshalHTTPSRecord(data []byte) (*HTTPSRecord, error) {
	result := &HTTPSRecord{}

	p := bytes.NewBuffer(data)

	priority := uint16(0)
	err := binary.Read(p, binary.BigEndian, &priority)
	if err != nil {
		return nil, err
	}

	result.Priority = priority

	// targetName is uncompressed: https://datatracker.ietf.org/doc/html/rfc9460/#section-2.2
	result.TargetName, err = readUncompressedDomain(p)
	if err != nil {
		return nil, err
	}

	for {
		if p.Len() == 0 {
			break
		}

		key := uint16(0)
		err = binary.Read(p, binary.BigEndian, &key)
		if err != nil {
			return nil, err
		}

		value, err := readArray16(p)
		if err != nil {
			return nil, err
		}

		switch key {
		case alpn:
			if result.ALPN != nil {
				return nil, fmt.Errorf("duplicate ALPN field")
			}

			alpn, err := readALPN(value)
			if err != nil {
				return nil, err
			}
			result.ALPN = alpn
		case ipv4Hint:
			if result.IPv4Hint != nil {
				return nil, fmt.Errorf("duplicate IPv4 hint field")
			}

			ipv4, err := readIPv4(value)
			if err != nil {
				return nil, err
			}
			result.IPv4Hint = ipv4
		case ech:
			if result.ECH != nil {
				return nil, fmt.Errorf("duplicate ECH field")
			}

			// https: //datatracker.ietf.org/doc/html/draft-ietf-tls-esni-22
			d, err := UnmarshalECHConfig(value)
			if err != nil {
				return nil, err
			}

			result.ECH = d
		case ipv6Hint:
			if result.IPv6Hint != nil {
				return nil, fmt.Errorf("duplicate IPv6 hint field")
			}

			ipv6, err := readIPv6(value)
			if err != nil {
				return nil, err
			}
			result.IPv6Hint = ipv6
		default:
			return nil, fmt.Errorf("invalid 65 key: %d", key)
		}
	}

	if p.Len() != 0 {
		return nil, fmt.Errorf("unexpected additional data in HTTPS record")
	}

	return result, nil
}

// TODO remove copying
func readALPN(data []byte) ([]string, error) {
	p := bytes.NewBuffer(data)
	parts := make([]string, 0)

	for {
		if p.Len() == 0 {
			break
		}
		part, err := readArray8(p)
		if err != nil {
			return nil, err
		}
		parts = append(parts, string(part))
	}

	return parts, nil
}

func readIPv4(data []byte) ([]net.IP, error) {
	if len(data)%4 != 0 {
		return nil, fmt.Errorf("invalid IPv4 length: %d", len(data))
	}

	count := len(data) / 4

	r := make([]net.IP, 0)
	for i := 0; i < count; i++ {
		index := 4 * i
		ip := net.IPv4(data[index+0], data[index+1], data[index+2], data[index+3])

		r = append(r, ip)
	}

	return r, nil
}

func readIPv6(data []byte) ([]net.IP, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("invalid IPv6 length: %d", len(data))
	}

	count := len(data) / 16

	r := make([]net.IP, 0)
	for i := 0; i < count; i++ {
		index := 16 * i
		var ip net.IP = data[index : index+16]

		r = append(r, ip)
	}

	return r, nil
}
