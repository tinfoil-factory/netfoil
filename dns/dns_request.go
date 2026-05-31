package dns

import (
	"bytes"
	"fmt"
)

func UnmarshalRequest(data []byte) (*Request, error) {
	// fmt.Printf("original: %s\n", base64.URLEncoding.EncodeToString(data))
	buffer := bytes.NewBuffer(data)

	header, err := readHeader(buffer)
	if err != nil {
		return nil, err
	}

	if header.NumberOfQuestions != 1 {
		return nil, fmt.Errorf("expected exactly one question, got %d", header.NumberOfQuestions)
	}

	if header.NumberOfAnswers != 0 {
		return nil, fmt.Errorf("expected no answers, got %d", header.NumberOfAnswers)
	}

	if header.NumberOfAuthorityRRs != 0 {
		return nil, fmt.Errorf("expected no authority RRs, got %d", header.NumberOfAuthorityRRs)
	}

	if header.NumberOfAdditionalRRs != 0 {
		return nil, fmt.Errorf("expected no additional RRs, got %d", header.NumberOfAdditionalRRs)
	}

	flags := UnmarshalFlags(header.Flags)

	if flags.QR == true {
		return nil, fmt.Errorf("expected query, got reply")
	}

	if flags.OPCODE != 0 {
		return nil, fmt.Errorf("expected standard query, got %d", flags.OPCODE)
	}

	if flags.AA == true {
		return nil, fmt.Errorf("unexpected flag AA set")
	}

	if flags.TC == true {
		return nil, fmt.Errorf("unexpected flag TC set")
	}

	// RD can be set or not set

	if flags.RA == true {
		return nil, fmt.Errorf("unexpected flag RA set")
	}

	if flags.Z == true {
		return nil, fmt.Errorf("unexpected flag Z set")
	}

	if flags.AD == true {
		return nil, fmt.Errorf("unexpected flag AD set")
	}

	if flags.CD == true {
		return nil, fmt.Errorf("unexpected flag CD set")
	}

	if flags.RCODE != 0 {
		return nil, fmt.Errorf("unexpected non-zero RCODE %d", flags.RCODE)
	}

	name, err := readDomain(data, buffer)
	if err != nil {
		return nil, err
	}

	t, err := readType(buffer)
	if err != nil {
		return nil, err
	}

	class, err := readClass(buffer)
	if err != nil {
		return nil, err
	}

	question := Question{
		Name:  name,
		Type:  t,
		Class: class,
	}

	if buffer.Len() != 0 {
		return nil, fmt.Errorf("unexpected data at the end")
	}

	return &Request{
		TransactionID: header.TransactionID,
		Flags:         flags,
		Question:      question,
	}, nil
}

func MarshalRequest(request *Request) ([]byte, error) {
	buffer := &bytes.Buffer{}

	flags := MarshalFlags(request.Flags)
	header := &Header{
		TransactionID:         request.TransactionID,
		Flags:                 flags,
		NumberOfQuestions:     1,
		NumberOfAnswers:       0,
		NumberOfAdditionalRRs: 0,
		NumberOfAuthorityRRs:  0,
	}

	err := writeHeader(buffer, header)
	if err != nil {
		return nil, err
	}

	err = writeDomain(buffer, request.Question.Name)
	if err != nil {
		return nil, err
	}

	err = writeType(buffer, request.Question.Type)
	if err != nil {
		return nil, err
	}

	err = writeClass(buffer, request.Question.Class)
	if err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}
