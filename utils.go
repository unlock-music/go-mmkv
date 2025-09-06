package go_mmkv

import "io"

func MMKVToMap(mmkv io.Reader, password []byte, crc io.Reader) (result map[string]string, err error) {
	parser, err := NewMMKVReader(mmkv, password, crc)
	if err != nil {
		return nil, err
	}

	result = make(map[string]string)

	for !parser.IsEOF() {
		key, err := parser.ReadString()
		if err != nil {
			return nil, err
		}
		value, err := parser.ReadStringValue()
		if err != nil {
			return nil, err
		}
		result[key] = value
	}
	return result, nil
}
