package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

func MarshalResponse(request *Request, response *Response) ([]byte, error) {
	var numberOfAnswers uint16
	var rcode ResponseCode

	// FIXME serialize response as is
	q := request.Questions[0]
	if q.Type == RecordTypeA {
		numberOfAnswers = uint16(len(response.Answers))
		rcode = response.Flags.RCODE
	} else if q.Type == RecordTypeAAAA {
		numberOfAnswers = uint16(len(response.Answers))
		rcode = response.Flags.RCODE
	} else if q.Type == RecordTypeHTTPS {
		numberOfAnswers = uint16(len(response.Answers))
		rcode = response.Flags.RCODE
	} else {
		numberOfAnswers = 0
		rcode = response.Flags.RCODE
	}

	f := Flags{
		QR: true, // this is a response
		// TODO handle other opcodes
		OPCODE: 0,
		// TODO pass AA answer vs leak underlying resolver?
		AA:    false,
		TC:    response.Flags.TC,
		RD:    request.Flags.RD,
		RA:    response.Flags.RA,
		Z:     0,
		RCODE: rcode,
	}

	packedFlags := MarshalFlags(&f)

	header := &Header{
		TransactionID:         request.TransactionID,
		Flags:                 packedFlags,
		NumberOfQuestions:     1,
		NumberOfAnswers:       numberOfAnswers,
		NumberOfAuthorityRRs:  0,
		NumberOfAdditionalRRs: 0,
	}

	rp := &bytes.Buffer{}
	err := writeHeader(rp, header)
	if err != nil {
		return nil, err
	}

	err = writeQuestion(rp, q)
	if err != nil {
		return nil, err
	}

	if q.Type == 1 || q.Type == 28 || q.Type == 65 {
		// Response
		for _, answer := range response.Answers {
			err = writeAnswer(rp, answer)
			if err != nil {
				return nil, err
			}
		}
	}

	return rp.Bytes(), nil
}

func UnmarshalResponse(data []byte) (*Response, error) {
	p := bytes.NewBuffer(data)

	header := &Header{}
	err := binary.Read(p, binary.BigEndian, header)
	if err != nil {
		return nil, err
	}

	flags := UnmarshalFlags(header.Flags)

	// https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
	questions := make([]Question, 0)
	for i := 0; i < int(header.NumberOfQuestions); i++ {
		name, err := readDomain(data, p)
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
	for i := 0; i < int(header.NumberOfAnswers); i++ {
		question, err := readDomain(data, p)
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
			Name:  question,
			Type:  t,
			Class: class,
			TTL:   ttl,
		}

		switch t {
		case RecordTypeA:
			ip := net.IPv4(rawData[0], rawData[1], rawData[2], rawData[3])
			a.IPv4 = ip.To4()
		case RecordTypeAAAA:
			ip := net.IP(rawData)
			a.IPv6 = ip
		case RecordTypeHTTPS:
			r, err := unmarshalHTTPSRecord(rawData)
			if err != nil {
				return nil, err
			}
			a.HTTPSRecord = r
		case RecordTypeCNAME:
			pb := bytes.NewBuffer(rawData)
			domain, err := readDomain(data, pb)
			if err != nil {
				return nil, err
			}

			if pb.Len() != 0 {
				return nil, fmt.Errorf("invalid CNAME record")
			}
			a.CNAME = domain
		}

		answers = append(answers, a)
	}

	// FIXME consume authority sections as well

	r := &Response{
		Flags:     flags,
		Questions: questions,
		Answers:   answers,
	}

	return r, nil
}
