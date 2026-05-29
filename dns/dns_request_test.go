package dns

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRequest(t *testing.T) {
	h := "JvwBAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ=="
	r, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}

	request, err := UnmarshalRequest(r)
	if err != nil {
		t.Fatal(err)
	}

	if request.Question.Name != "google.com" {
		t.Errorf("expected question %s, got %s", "google.com", request.Question.Name)
	}

	marshalled, err := MarshalRequest(request)

	if !bytes.Equal(marshalled, r) {
		t.Errorf("expected marshalled %s, got %s", hex.EncodeToString(r), hex.EncodeToString(marshalled))
	}
}

func TestUnexpectedDataAtTheEnd(t *testing.T) {
	h := "JvwBAAABAAAAAAAABmdvb2dsZQNjb20AAAEAAQ=="
	r, err := base64.URLEncoding.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}

	// Additional data
	r = append(r, 1)

	_, err = UnmarshalRequest(r)
	if err == nil {
		t.Fatal("expected error, got none")
	}

	expectedError := "unexpected data at the end"
	if err.Error() != expectedError {
		t.Errorf("expected error %s, got %s", expectedError, err.Error())
	}
}

func TestMultipleQuestions(t *testing.T) {
	invalidNumberOfQuestions := []uint16{0, 2}

	for _, n := range invalidNumberOfQuestions {
		buffer := bytes.NewBuffer(nil)

		err := writeHeader(buffer, &Header{
			NumberOfQuestions: n,
		})
		if err != nil {
			t.Fatal(err)
		}

		_, err = UnmarshalRequest(buffer.Bytes())
		if err == nil {
			t.Fatal("expected error, got none")
		}

		expectedError := fmt.Sprintf("expected exactly one question, got %d", n)
		if err.Error() != expectedError {
			t.Errorf("expected error %s, got %s", expectedError, err.Error())
		}
	}
}

func TestNonEmptyAnswers(t *testing.T) {
	buffer := bytes.NewBuffer(nil)

	err := writeHeader(buffer, &Header{
		NumberOfQuestions: 1,
		NumberOfAnswers:   1,
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = UnmarshalRequest(buffer.Bytes())
	if err == nil {
		t.Fatal("expected error, got none")
	}

	expectedError := "expected no answers, got 1"
	if err.Error() != expectedError {
		t.Errorf("expected error %s, got %s", expectedError, err.Error())
	}
}

func TestNonEmptyAuthorityRR(t *testing.T) {
	buffer := bytes.NewBuffer(nil)

	err := writeHeader(buffer, &Header{
		NumberOfQuestions:    1,
		NumberOfAuthorityRRs: 1,
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = UnmarshalRequest(buffer.Bytes())
	if err == nil {
		t.Fatal("expected error, got none")
	}

	expectedError := "expected no authority RRs, got 1"
	if err.Error() != expectedError {
		t.Errorf("expected error %s, got %s", expectedError, err.Error())
	}
}

func TestNonEmptyAdditionalRR(t *testing.T) {
	buffer := bytes.NewBuffer(nil)

	err := writeHeader(buffer, &Header{
		NumberOfQuestions:     1,
		NumberOfAdditionalRRs: 1,
	})

	if err != nil {
		t.Fatal(err)
	}

	_, err = UnmarshalRequest(buffer.Bytes())
	if err == nil {
		t.Fatal("expected error, got none")
	}

	expectedError := "expected no additional RRs, got 1"
	if err.Error() != expectedError {
		t.Errorf("expected error %s, got %s", expectedError, err.Error())
	}
}
