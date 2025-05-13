package dns

import (
	"bytes"
)

func UnmarshalRequest(data []byte) (*Request, error) {
	// fmt.Printf("original: %s\n", base64.URLEncoding.EncodeToString(data))
	buffer := bytes.NewBuffer(data)

	header, err := readHeader(buffer)
	if err != nil {
		return nil, err
	}

	flags := UnmarshalFlags(header.Flags)

	questions := make([]Question, 0)
	for i := 0; i < int(header.NumberOfQuestions); i++ {
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

		questions = append(questions, Question{
			Name:  name,
			Type:  t,
			Class: class,
		})
	}

	// FIXME answer, authorityRRs and additionalRRs

	return &Request{
		TransactionID: header.TransactionID,
		Flags:         flags,
		Questions:     questions,
	}, nil
}

func MarshalRequest(request *Request) ([]byte, error) {
	buffer := &bytes.Buffer{}

	flags := MarshalFlags(request.Flags)
	header := &Header{
		TransactionID:         request.TransactionID,
		Flags:                 flags,
		NumberOfQuestions:     uint16(len(request.Questions)),
		NumberOfAnswers:       0,
		NumberOfAdditionalRRs: 0,
		NumberOfAuthorityRRs:  0,
	}

	err := writeHeader(buffer, header)
	if err != nil {
		return nil, err
	}

	for _, question := range request.Questions {
		err = writeDomain(buffer, question.Name)
		if err != nil {
			return nil, err
		}

		err = writeType(buffer, question.Type)
		if err != nil {
			return nil, err
		}

		err = writeClass(buffer, question.Class)
		if err != nil {
			return nil, err
		}
	}

	return buffer.Bytes(), nil
}
