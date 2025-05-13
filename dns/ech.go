package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

type ECHConfig struct {
	Version           uint16
	HPKEKeyConfig     HPKEKeyConfig
	MaximumNameLength uint8
	PublicName        string
	Extensions        []byte
}

type HPKEKeyConfig struct {
	ConfigID                  uint8
	HPKEKEMID                 uint16
	HPKEPublicKey             []byte
	HPKESymmetricCipherSuites []HPKESymmetricCipherSuite
}
type HPKESymmetricCipherSuite struct {
	HPKEKDFID  uint16
	HPKEAEADID uint16
}

func UnmarshalECHConfig(data []byte) ([]ECHConfig, error) {
	buffer := bytes.NewBuffer(data)

	// TODO verify
	var outerLength uint16
	err := binary.Read(buffer, binary.BigEndian, &outerLength)
	if err != nil {
		return nil, err
	}

	result := make([]ECHConfig, 0)
	for {
		var version uint16
		err = binary.Read(buffer, binary.BigEndian, &version)
		if err != nil {
			return nil, err
		}

		var length uint16
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			return nil, err
		}

		innerBuffer := bytes.NewBuffer(buffer.Bytes()[:length])
		buffer = bytes.NewBuffer(buffer.Bytes()[length:])

		if version != 0xfe0d {
			// The spec says to ignore unknown config
			// TODO decide to fail instead
			continue
		}

		echConfig, err := unmarshalInner(version, innerBuffer)
		if err != nil {
			return nil, err
		}
		result = append(result, *echConfig)

		if buffer.Len() == 0 {
			break
		}
	}

	return result, nil
}

func unmarshalInner(version uint16, buffer *bytes.Buffer) (*ECHConfig, error) {
	var configID byte
	err := binary.Read(buffer, binary.BigEndian, &configID)
	if err != nil {
		return nil, err
	}

	var hpkekemid uint16
	err = binary.Read(buffer, binary.BigEndian, &hpkekemid)
	if err != nil {
		return nil, err
	}

	hpkePublicKey, err := readArray16(buffer)
	if err != nil {
		return nil, err
	}

	var cipherSuitesLength uint16
	err = binary.Read(buffer, binary.BigEndian, &cipherSuitesLength)
	if err != nil {
		return nil, err
	}

	cipherSuites := make([]HPKESymmetricCipherSuite, 0)
	for i := 0; i < int(cipherSuitesLength/4); i++ {
		var hpkekdfid uint16
		err = binary.Read(buffer, binary.BigEndian, &hpkekdfid)
		if err != nil {
			return nil, err
		}

		var hpkeaeadid uint16
		err = binary.Read(buffer, binary.BigEndian, &hpkeaeadid)
		if err != nil {
			return nil, err
		}

		cipherSuites = append(cipherSuites, HPKESymmetricCipherSuite{
			HPKEKDFID:  hpkekdfid,
			HPKEAEADID: hpkeaeadid,
		})
	}

	var maximumNameLength byte
	err = binary.Read(buffer, binary.BigEndian, &maximumNameLength)
	if err != nil {
		return nil, err
	}

	name, err := readArray8(buffer)
	if err != nil {
		return nil, err
	}

	extensions, err := readArray16(buffer)
	if err != nil {
		return nil, err
	}

	return &ECHConfig{
		Version: version,
		HPKEKeyConfig: HPKEKeyConfig{
			ConfigID:                  configID,
			HPKEKEMID:                 hpkekemid,
			HPKEPublicKey:             hpkePublicKey,
			HPKESymmetricCipherSuites: cipherSuites,
		},
		MaximumNameLength: maximumNameLength,
		PublicName:        string(name),
		Extensions:        extensions,
	}, nil
}

func MarshalECHConfig(echConfig []ECHConfig) ([]byte, error) {
	innerList := make([][]byte, 0)

	totalSize := 0
	for _, config := range echConfig {
		inner, err := marshalInner(&config)
		if err != nil {
			return nil, err
		}

		innerList = append(innerList, inner)
		totalSize += len(inner)
	}

	outerLength := totalSize
	if outerLength > 65536 {
		return nil, fmt.Errorf("ECH outer overflow")
	}

	final := bytes.Buffer{}
	err := binary.Write(&final, binary.BigEndian, uint16(outerLength))
	if err != nil {
		return nil, err
	}

	for _, inner := range innerList {
		l, err := final.Write(inner)
		if err != nil {
			return nil, err
		}

		if l != len(inner) {
			return nil, fmt.Errorf("ECH outer underflow")
		}
	}

	return final.Bytes(), nil
}

func marshalInner(echConfig *ECHConfig) ([]byte, error) {
	buffer := bytes.Buffer{}

	err := binary.Write(&buffer, binary.BigEndian, echConfig.HPKEKeyConfig.ConfigID)
	if err != nil {
		return nil, err
	}

	err = binary.Write(&buffer, binary.BigEndian, echConfig.HPKEKeyConfig.HPKEKEMID)
	if err != nil {
		return nil, err
	}

	err = writeArray16(&buffer, echConfig.HPKEKeyConfig.HPKEPublicKey)
	if err != nil {
		return nil, err
	}

	suitesLength := len(echConfig.HPKEKeyConfig.HPKESymmetricCipherSuites) * 4
	if suitesLength > 65536 {
		return nil, errors.New("ECH ciphers overflow")
	}

	err = binary.Write(&buffer, binary.BigEndian, uint16(suitesLength))

	for _, suite := range echConfig.HPKEKeyConfig.HPKESymmetricCipherSuites {
		err = binary.Write(&buffer, binary.BigEndian, suite.HPKEKDFID)
		if err != nil {
			return nil, err
		}

		err = binary.Write(&buffer, binary.BigEndian, suite.HPKEAEADID)
		if err != nil {
			return nil, err
		}
	}

	err = binary.Write(&buffer, binary.BigEndian, echConfig.MaximumNameLength)
	if err != nil {
		return nil, err
	}

	err = writeArray8(&buffer, []byte(echConfig.PublicName))
	if err != nil {
		return nil, err
	}

	err = writeArray16(&buffer, echConfig.Extensions)
	if err != nil {
		return nil, err
	}

	res := bytes.Buffer{}

	err = binary.Write(&res, binary.BigEndian, echConfig.Version)
	if err != nil {
		return nil, err
	}

	innerLength := buffer.Len()
	if innerLength > 65536 {
		return nil, fmt.Errorf("ECH inner overflow")
	}

	err = binary.Write(&res, binary.BigEndian, uint16(innerLength))
	if err != nil {
		return nil, err
	}

	l, err := res.Write(buffer.Bytes())
	if err != nil {
		return nil, err
	}

	if l != innerLength {
		return nil, fmt.Errorf("ECH inner underflow")
	}

	return res.Bytes(), nil
}
