package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Request struct {
	TransactionID uint16
	Flags         *Flags

	Questions []Question
}

type Response struct {
	Flags *Flags

	Questions []Question
	Answers   []Answer
}

type Question struct {
	Name  string
	Type  RecordType
	Class ClassType
}

type Answer struct {
	Name  string
	Type  RecordType
	Class ClassType
	TTL   uint32

	IPv4        net.IP
	IPv6        net.IP
	HTTPSRecord *HTTPSRecord
	CNAME       string
}
type RecordType uint16
type ClassType uint16
type ResponseCode byte

const (
	// RecordTypeA etc https://en.wikipedia.org/wiki/List_of_DNS_record_types
	RecordTypeA     RecordType = 1
	RecordTypeCNAME RecordType = 5
	RecordTypeAAAA  RecordType = 28
	RecordTypeHTTPS RecordType = 65

	ClassTypeIN ClassType = 1

	// ResponseCodeNoError etc https://www.rfc-editor.org/rfc/rfc6895.html#section-2.3
	ResponseCodeNoError     ResponseCode = 0
	ResponseCodeFormatError ResponseCode = 1
	ResponseCodeServFail    ResponseCode = 2
	ResponseCodeNXDomain    ResponseCode = 3
	ResponseCodeNotImp      ResponseCode = 4
	ResponseCodeRefused     ResponseCode = 5
)

func (r RecordType) Name() string {
	switch r {
	case RecordTypeA:
		return "A"
	case RecordTypeCNAME:
		return "CNAME"
	case RecordTypeAAAA:
		return "AAAA"
	case RecordTypeHTTPS:
		return "HTTPS"
	default:
		return strconv.Itoa(int(r))
	}
}

type Header struct {
	TransactionID         uint16
	Flags                 uint16
	NumberOfQuestions     uint16
	NumberOfAnswers       uint16
	NumberOfAuthorityRRs  uint16
	NumberOfAdditionalRRs uint16
}

type Flags struct {
	QR     bool
	OPCODE byte
	AA     bool
	TC     bool
	RD     bool
	RA     bool
	Z      byte
	RCODE  ResponseCode
}

func UnmarshalFlags(data uint16) *Flags {
	qr := (data >> 15) & 0b1
	opcode := (data >> 11) & 0b1111
	aa := (data >> 10) & 0b1
	tc := (data >> 9) & 0b1
	rd := (data >> 8) & 0b1
	ra := (data >> 7) & 0b1
	z := (data >> 4) & 0b111
	rcode := data & 0b1111

	return &Flags{
		QR:     qr == 1,
		OPCODE: byte(opcode),
		AA:     aa == 1,
		TC:     tc == 1,
		RD:     rd == 1,
		RA:     ra == 1,
		Z:      byte(z),
		RCODE:  ResponseCode(rcode),
	}
}

func MarshalFlags(flags *Flags) uint16 {
	var result uint16 = 0

	result |= boolToUint16(flags.QR) << 15
	result |= uint16(flags.OPCODE) << 11
	result |= boolToUint16(flags.AA) << 10
	result |= boolToUint16(flags.TC) << 9
	result |= boolToUint16(flags.RD) << 8
	result |= boolToUint16(flags.RA) << 7
	result |= uint16(flags.Z) << 4
	result |= uint16(flags.RCODE)

	return result
}

func boolToUint16(b bool) uint16 {
	if b {
		return 1
	} else {
		return 0
	}
}

func writeQuestion(buffer *bytes.Buffer, question Question) error {
	err := writeDomain(buffer, question.Name)
	if err != nil {
		return err
	}

	err = writeType(buffer, question.Type)
	if err != nil {
		return err
	}

	err = writeClass(buffer, question.Class)
	if err != nil {
		return err
	}

	return nil
}

func writeAnswer(buffer *bytes.Buffer, answer Answer) error {
	err := writeDomain(buffer, answer.Name)
	if err != nil {
		return err
	}

	err = writeType(buffer, answer.Type)
	if err != nil {
		return err
	}

	err = writeClass(buffer, answer.Class)
	if err != nil {
		return err
	}

	err = binary.Write(buffer, binary.BigEndian, answer.TTL)
	if err != nil {
		return err
	}

	if answer.Type == RecordTypeA {
		err := writeArray16(buffer, answer.IPv4)
		if err != nil {
			return err
		}
	} else if answer.Type == RecordTypeCNAME {
		parts := strings.Split(answer.CNAME, ".")
		s := len(parts) + 1
		for _, part := range parts {
			s += len(part)
		}

		var rdLength = uint16(s)
		err = binary.Write(buffer, binary.BigEndian, rdLength)
		if err != nil {
			return err
		}

		err = writeDomain(buffer, answer.CNAME)
		if err != nil {
			return err
		}
	} else if answer.Type == RecordTypeAAAA {
		err := writeArray16(buffer, answer.IPv6)
		if err != nil {
			return err
		}
	} else if answer.Type == RecordTypeHTTPS {
		r, err := marshalHTTPSRecord(answer.HTTPSRecord)
		if err != nil {
			return err
		}

		err = writeArray16(buffer, r)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("unsupported answer type %d", answer.Type)
	}

	return nil
}

func writeDomain(buffer *bytes.Buffer, domain string) error {
	if len(domain) != 0 {
		parts := strings.Split(domain, ".")
		for _, part := range parts {
			l := byte(len(part))
			err := buffer.WriteByte(l)
			if err != nil {
				return err
			}

			length, err := buffer.WriteString(part)
			if err != nil {
				return err
			}

			if length != len(part) {
				return fmt.Errorf("invalid length: %d", length)
			}
		}
	}

	buffer.WriteByte(0)

	return nil
}

func readDomain(data []byte, buffer *bytes.Buffer) (string, error) {
	currentBuffer := buffer
	parts := make([]string, 0)
	visitedOffsets := make(map[uint16]struct{})

	for {
		targetLength, err := currentBuffer.ReadByte()
		if err != nil {
			return "", err
		}

		// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.4
		pointerIndicator := (int(targetLength) >> 6) & 0b11
		if pointerIndicator == 3 {
			pointerSecondHalf, err := currentBuffer.ReadByte()
			if err != nil {
				return "", err
			}
			offset := uint16(targetLength&0b00111111)<<8 | uint16(pointerSecondHalf)
			// FIXME write test for loop detection
			// TODO only allow pointing to previous data?
			_, found := visitedOffsets[offset]
			if found {
				return "", fmt.Errorf("loop detected while decoding domain name")
			}

			visitedOffsets[offset] = struct{}{}

			currentBuffer = bytes.NewBuffer(data[offset:])

			continue
		}

		if targetLength == 0 {
			break
		}

		section := make([]byte, targetLength)
		read, err := currentBuffer.Read(section)
		if err != nil {
			return "", err
		}
		if read != int(targetLength) {
			return "", fmt.Errorf("read %d, expected %d", read, targetLength)
		}

		parts = append(parts, string(section))
	}

	return strings.Join(parts, "."), nil
}

func readUncompressedDomain(buffer *bytes.Buffer) (string, error) {
	parts := make([]string, 0)
	for {
		targetLength, err := buffer.ReadByte()
		if err != nil {
			return "", err
		}
		if targetLength == 0 {
			break
		}

		section := make([]byte, targetLength)
		readLength, err := buffer.Read(section)
		if err != nil {
			return "", err
		}

		if readLength != int(targetLength) {
			return "", fmt.Errorf("read %d, expected %d", readLength, targetLength)
		}

		parts = append(parts, string(section))
	}

	return strings.Join(parts, "."), nil
}

func readArray8(buffer *bytes.Buffer) ([]byte, error) {
	targetLength, err := buffer.ReadByte()
	if err != nil {
		return nil, err
	}

	value := make([]byte, targetLength)
	readLength, err := buffer.Read(value)
	if err != nil {
		return nil, err
	}

	if readLength != int(targetLength) {
		return nil, fmt.Errorf("read %d, expected %d", readLength, targetLength)
	}

	return value, nil
}

func writeArray8(buffer *bytes.Buffer, value []byte) error {
	candidateLength := len(value)
	if candidateLength > 255 {
		return fmt.Errorf("length larger than 1 byte: %d", candidateLength)
	}

	targetLength := uint8(candidateLength)

	err := binary.Write(buffer, binary.BigEndian, targetLength)
	if err != nil {
		return err
	}

	writtenLength, err := buffer.Write(value)
	if err != nil {
		return err
	}

	if writtenLength != int(targetLength) {
		return fmt.Errorf("wrote %d, expected %d", writtenLength, targetLength)
	}

	return nil
}

func writeArray16(buffer *bytes.Buffer, value []byte) error {
	candidateLength := len(value)
	if candidateLength > 65536 {
		return fmt.Errorf("length larger than 2 bytes: %d", candidateLength)
	}

	targetLength := uint16(candidateLength)

	err := binary.Write(buffer, binary.BigEndian, targetLength)
	if err != nil {
		return err
	}

	writtenLength, err := buffer.Write(value)
	if err != nil {
		return err
	}

	if writtenLength != int(targetLength) {
		return fmt.Errorf("wrote %d, expected %d", writtenLength, targetLength)
	}

	return nil
}

func readArray16(buffer *bytes.Buffer) ([]byte, error) {
	targetLength := uint16(0)
	err := binary.Read(buffer, binary.BigEndian, &targetLength)
	if err != nil {
		return nil, err
	}

	value := make([]byte, targetLength)
	readLength, err := buffer.Read(value)
	if err != nil {
		return nil, err
	}

	if readLength != int(targetLength) {
		return nil, fmt.Errorf("read %d, expected %d", readLength, targetLength)
	}

	return value, nil
}

func readHeader(buffer *bytes.Buffer) (*Header, error) {
	header := &Header{}
	err := binary.Read(buffer, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	return header, nil
}
func writeHeader(buffer *bytes.Buffer, header *Header) error {
	return binary.Write(buffer, binary.BigEndian, header)
}

// https://en.wikipedia.org/wiki/List_of_DNS_record_types
func readType(buffer *bytes.Buffer) (RecordType, error) {
	var t RecordType
	err := binary.Read(buffer, binary.BigEndian, &t)
	if err != nil {
		return 0, err
	}

	return t, nil
}

func writeType(buffer *bytes.Buffer, t RecordType) error {
	return binary.Write(buffer, binary.BigEndian, t)
}

func readClass(buffer *bytes.Buffer) (ClassType, error) {
	var c ClassType
	err := binary.Read(buffer, binary.BigEndian, &c)
	if err != nil {
		return 0, err
	}

	if c != ClassTypeIN {
		return 0, fmt.Errorf("invalid class %d", c)
	}

	return c, nil
}

func writeClass(buffer *bytes.Buffer, c ClassType) error {
	return binary.Write(buffer, binary.BigEndian, c)
}
