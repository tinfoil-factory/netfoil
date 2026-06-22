package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	maxNumberOfCnameRecords = 10
	maxNumberOfIPv4Records  = 10
	maxNumberOfIPv6Records  = 10
	maxNumberOfHTTPSRecords = 10
	maxNumberOfIPv4Hints    = 10
	maxNumberOfIPv6Hints    = 10
	maxNumberOfECH          = 10
	headerLength            = 12
	tcpMaxPayloadSize       = 65535
)

func MarshalResponse(request *Request, response *Response, isTCP bool) ([]byte, error) {
	q := request.Question
	switch q.Type {
	case RecordTypeA:
	case RecordTypeAAAA:
	case RecordTypeHTTPS:
	default:
		return nil, fmt.Errorf("unsupported question type")
	}

	truncation := false
	maxLength := int(request.RequestorPayloadSize)
	initialBufferLength := maxLength
	if isTCP {
		maxLength = tcpMaxPayloadSize
		initialBufferLength = int(ednsMaxPayloadSize)
	}

	questionAndAnswerBuffer := bytes.NewBuffer(make([]byte, 0, initialBufferLength))

	headerPlaceholder := make([]byte, headerLength)
	_, err := questionAndAnswerBuffer.Write(headerPlaceholder)
	if err != nil {
		return nil, err
	}

	err = writeQuestion(questionAndAnswerBuffer, q)
	if err != nil {
		return nil, err
	}

	numberOfAnswers := uint16(0)
	for _, answer := range response.Answers {
		answerBuffer := &bytes.Buffer{}
		err = writeAnswer(answerBuffer, answer)
		if err != nil {
			return nil, err
		}

		if maxLength-questionAndAnswerBuffer.Len()-answerBuffer.Len() >= 0 {
			questionAndAnswerBuffer.Write(answerBuffer.Bytes())
			numberOfAnswers++
		} else {
			// TODO what to do in this case?
			if !isTCP {
				truncation = true
			}
			break
		}
	}

	f := Flags{
		QR: true, // this is a response
		// TODO handle other opcodes
		OPCODE: 0,
		// TODO pass AA answer vs leak underlying resolver?
		AA:    false,
		TC:    truncation,
		RD:    request.Flags.RD,
		RA:    true,
		Z:     false,
		AD:    false,
		CD:    false,
		RCODE: response.Flags.RCODE,
	}

	packedFlags := MarshalFlags(f)

	header := &Header{
		TransactionID:         request.TransactionID,
		Flags:                 packedFlags,
		NumberOfQuestions:     1,
		NumberOfAnswers:       numberOfAnswers,
		NumberOfAuthorityRRs:  0,
		NumberOfAdditionalRRs: 0,
	}

	result := questionAndAnswerBuffer.Bytes()

	headerBuffer := &bytes.Buffer{}
	err = writeHeader(headerBuffer, header)
	if err != nil {
		return nil, err
	}

	headerBytes := headerBuffer.Bytes()
	if len(headerBytes) != headerLength {
		return nil, fmt.Errorf("wrong header length, expected %d, got %d", headerLength, len(headerBytes))
	}

	copy(result[0:12], headerBytes)

	if len(result) > maxLength {
		return nil, fmt.Errorf("response too long, expected max %d, got %d)", maxLength, len(result))
	}

	return result, nil
}

func MarshalEmptyFormatError(buffer []byte) ([]byte, error) {
	var id uint16 = 0
	if len(buffer) > 1 {
		id = binary.BigEndian.Uint16(buffer[0:2])
	}

	flags := Flags{
		QR:     true, // this is a response
		OPCODE: 0,
		RCODE:  ResponseCodeFormatError,
		RA:     true,
	}

	header := &Header{
		TransactionID:         id,
		Flags:                 MarshalFlags(flags),
		NumberOfQuestions:     0,
		NumberOfAnswers:       0,
		NumberOfAuthorityRRs:  0,
		NumberOfAdditionalRRs: 0,
	}

	rp := &bytes.Buffer{}
	err := writeHeader(rp, header)
	if err != nil {
		return nil, err
	}

	return rp.Bytes(), nil
}

func MarshalServerFailure(request *Request) ([]byte, error) {
	flags := Flags{
		QR:     true, // this is a response
		OPCODE: 0,
		RCODE:  ResponseCodeServFail,
		RA:     true,
	}

	header := &Header{
		TransactionID:         request.TransactionID,
		Flags:                 MarshalFlags(flags),
		NumberOfQuestions:     1,
		NumberOfAnswers:       0,
		NumberOfAuthorityRRs:  0,
		NumberOfAdditionalRRs: 0,
	}

	rp := &bytes.Buffer{}
	err := writeHeader(rp, header)
	if err != nil {
		return nil, err
	}

	err = writeQuestion(rp, request.Question)
	if err != nil {
		return nil, err
	}

	return rp.Bytes(), nil
}

func MarshalNotImplementedResponse(request *Request) ([]byte, error) {
	flags := Flags{
		QR:     true, // this is a response
		OPCODE: 0,
		RCODE:  ResponseCodeNotImp,
		RA:     true,
	}

	header := &Header{
		TransactionID:         request.TransactionID,
		Flags:                 MarshalFlags(flags),
		NumberOfQuestions:     1,
		NumberOfAnswers:       0,
		NumberOfAuthorityRRs:  0,
		NumberOfAdditionalRRs: 0,
	}

	rp := &bytes.Buffer{}
	err := writeHeader(rp, header)
	if err != nil {
		return nil, err
	}

	err = writeQuestion(rp, request.Question)
	if err != nil {
		return nil, err
	}

	return rp.Bytes(), nil
}

func generateBlockResponse() *Response {
	var response *Response
	flags := Flags{
		QR:     true, // this is a response
		OPCODE: 0,
		RCODE:  ResponseCodeNXDomain,
		RA:     true,
	}

	response = &Response{
		Flags:   flags,
		Answers: nil,
	}

	return response
}

func UnmarshalResponse(data []byte) (*Response, error) {
	p := bytes.NewBuffer(data)

	header := &Header{}
	err := binary.Read(p, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	flags := UnmarshalFlags(header.Flags)

	if !(flags.RCODE == ResponseCodeNoError || flags.RCODE == ResponseCodeNXDomain) {
		return nil, fmt.Errorf("unexpected response code %s", flags.RCODE.Name())
	}

	if flags.TC {
		return nil, fmt.Errorf("TC not allowed in response")
	}

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	questions := make([]Question, 0)
	for i := 0; i < int(header.NumberOfQuestions); i++ {
		name, err := readDomain(data, p, true)
		if err != nil {
			return nil, err
		}

		var t RecordType
		err = binary.Read(p, binary.BigEndian, &t)
		if err != nil {
			return nil, err
		}

		var class ClassType
		err = binary.Read(p, binary.BigEndian, &class)
		if err != nil {
			return nil, err
		}

		questions = append(questions, Question{
			Name:  name,
			Type:  t,
			Class: class,
		})
	}

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.3
	answers := make([]Answer, 0)
	cnames := make(map[string]struct{})
	IPv4Count := 0
	IPv6Count := 0
	HTTPSCount := 0
	for i := 0; i < int(header.NumberOfAnswers); i++ {
		name, err := readDomain(data, p, true)
		if err != nil {
			return nil, err
		}

		var t RecordType
		err = binary.Read(p, binary.BigEndian, &t)
		if err != nil {
			return nil, err
		}

		var class ClassType
		err = binary.Read(p, binary.BigEndian, &class)
		if err != nil {
			return nil, err
		}

		var ttl uint32
		err = binary.Read(p, binary.BigEndian, &ttl)
		if err != nil {
			return nil, err
		}

		rawData, err := readArray16(p)
		if err != nil {
			return nil, err
		}

		a := Answer{
			Name:  name,
			Type:  t,
			Class: class,
			TTL:   ttl,
		}

		switch t {
		case RecordTypeA:
			if len(rawData) != 4 {
				return nil, fmt.Errorf("invalid IPv4 length in response")
			}

			ip := net.IPv4(rawData[0], rawData[1], rawData[2], rawData[3])
			a.IPv4 = ip.To4()

			IPv4Count++
			if IPv4Count > maxNumberOfIPv4Records {
				return nil, fmt.Errorf("too many IPv4 records")
			}
		case RecordTypeAAAA:
			if len(rawData) != 16 {
				return nil, fmt.Errorf("invalid IPv6 length in response")
			}

			ip := net.IP(rawData)
			a.IPv6 = ip

			IPv6Count++
			if IPv6Count > maxNumberOfIPv6Records {
				return nil, fmt.Errorf("too many IPv4 records")
			}
		case RecordTypeHTTPS:
			r, err := unmarshalHTTPSRecord(rawData)
			if err != nil {
				return nil, err
			}
			a.HTTPSRecord = *r

			HTTPSCount++
			if HTTPSCount > maxNumberOfHTTPSRecords {
				return nil, fmt.Errorf("too many IPv4 records")
			}
		case RecordTypeCNAME:
			pb := bytes.NewBuffer(rawData)
			domain, err := readDomain(data, pb, true)
			if err != nil {
				return nil, err
			}

			if pb.Len() != 0 {
				return nil, fmt.Errorf("invalid CNAME record")
			}
			a.CNAME = domain

			_, found := cnames[name]
			if found {
				return nil, fmt.Errorf("duplicate CNAME record")
			}
			cnames[name] = struct{}{}

			if len(cnames) > maxNumberOfCnameRecords {
				return nil, fmt.Errorf("too many CNAME records")
			}
		}

		answers = append(answers, a)
	}

	if flags.RCODE == ResponseCodeNXDomain && len(answers) != len(cnames) {
		return nil, fmt.Errorf("non-CNAME answers in a NXDomain response")
	}

	// FIXME consume authority sections as well

	r := &Response{
		Flags:     flags,
		Questions: questions,
		Answers:   answers,
	}

	return r, nil
}
