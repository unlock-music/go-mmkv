package go_mmkv

import (
	"encoding/binary"
	"fmt"
	"io"
)

type MMKVReader struct {
	reader io.Reader
	offset int64
	size   int64
}

// NewMMKVReader creates a new MMKVParser instance.
// mmkv is the main MMKV file reader, while crc can be nil if the file is not encrypted.
func NewMMKVReader(mmkv io.Reader, password []byte, crc io.Reader) (inst *MMKVReader, err error) {
	buf_payload_len := make([]byte, 4)
	_, err = mmkv.Read(buf_payload_len)
	if err != nil {
		return nil, err
	}

	if password != nil && crc != nil {
		crc_buffer := make([]byte, 0x0C+16)
		n, err := crc.Read(crc_buffer)
		if err != nil {
			return nil, err
		}
		if n != len(crc_buffer) {
			return nil, fmt.Errorf("NewMMKVParser: crc read EOF: got %d bytes, expected %d bytes", n, len(crc_buffer))
		}
		iv := crc_buffer[0x0C : 0x0C+16]
		mmkv, err = NewMMKVCrypto(mmkv, password, iv)
		if err != nil {
			return nil, fmt.Errorf("NewMMKVParser: init crypto fail: %v", err)
		}
	}

	payload_len := int64(binary.LittleEndian.Uint32(buf_payload_len))

	inst = &MMKVReader{
		reader: mmkv,
		offset: 4,
		size:   payload_len + 4,
	}
	inst.ReadInt()

	return inst, nil
}

func (p *MMKVReader) BytesAvailable() int64 {
	return p.size - p.offset
}

func (p *MMKVReader) IsEOF() bool {
	return p.offset >= p.size
}

func (p *MMKVReader) readByte() (value byte, err error) {
	if p.BytesAvailable() < 1 {
		return 0, io.EOF
	}

	buf := make([]byte, 1)
	n, err := p.reader.Read(buf)
	if err != nil {
		return 0, err
	}

	p.offset += int64(n)
	return buf[0], nil
}

func (p *MMKVReader) ReadInt() (value uint64, err error) {
	value, shift := 0, 0

	for {
		b, err := p.readByte()
		if err != nil {
			return 0, err
		}

		value |= uint64(b&0x7f) << shift
		shift += 7

		if b&0x80 == 0 {
			break
		}
	}

	return value, nil
}

func (p *MMKVReader) ReadIntSafe(maxBytes uint64) (value uint64, bytesRead uint64, err error) {
	bytesRead = 0
	value, shift := 0, 0

	for bytesRead < maxBytes {
		b, err := p.readByte()
		if err != nil {
			return value, bytesRead, err
		}

		bytesRead += 1

		value |= uint64(b&0x7f) << shift
		shift += 7

		if b&0x80 == 0 {
			return value, bytesRead, nil
		}
	}

	return 0, bytesRead, fmt.Errorf("ReadIntSafe: exceeded maxBytes %d", maxBytes)
}

func (p *MMKVReader) ReadBytes(n int64) (data []byte, err error) {
	if p.BytesAvailable() < n {
		return nil, io.EOF
	}

	buf := make([]byte, n)
	readBytes, err := p.reader.Read(buf)
	if err != nil {
		return nil, err
	}
	if readBytes != int(n) {
		return nil, io.ErrUnexpectedEOF
	}

	p.offset += int64(readBytes)
	return buf[:readBytes], nil
}

func (p *MMKVReader) ReadStringSafe(maxBytes uint64) (value string, bytesRead uint64, err error) {
	// String [
	//   len: int,
	//   data: byte[int], # utf-8
	// ]

	len, bytesRead, err := p.ReadIntSafe(maxBytes)
	if err != nil {
		return "", bytesRead, err
	}

	maxBytes -= bytesRead
	strlenToRead := min(maxBytes, len)

	data, err := p.ReadBytes(int64(strlenToRead))
	if err != nil {
		return "", bytesRead, err
	}
	bytesRead += uint64(strlenToRead)

	return string(data), bytesRead, nil
}

func (p *MMKVReader) ReadString() (value string, err error) {
	// String [
	//   len: int,
	//   data: byte[int], # utf-8
	// ]

	len, err := p.ReadInt()
	if err != nil {
		return "", err
	}

	data, err := p.ReadBytes(int64(len))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func (p *MMKVReader) ReadKey() (string, error) {
	return p.ReadString()
}

func (p *MMKVReader) ReadStringValue() (value string, err error) {
	// Container [
	//   len: int,
	//   data: variant
	// ]
	container_len, err := p.ReadInt()
	if err != nil {
		return "", err
	}

	expectedOffset := p.offset + int64(container_len)
	value, bytesRead, err := p.ReadStringSafe(container_len)
	if err != nil {
		return "", fmt.Errorf("ReadStringValue: could not safely read container: %v", err)
	}
	fmt.Printf("bytesRead: %d, container_len: %d\n", bytesRead, container_len)
	if bytesRead < container_len {
		// skip remaining bytes
		skipBytes := int64(container_len - bytesRead)
		_, err = p.ReadBytes(skipBytes)
		if err != nil {
			return "", fmt.Errorf("ReadStringValue: could not skip remaining bytes: %v", err)
		}
	}

	if p.offset != expectedOffset {
		return "", fmt.Errorf("ReadStringValue: offset mismatch (expect: %d, actual: %d)", expectedOffset, p.offset)
	}
	return value, nil
}

func (p *MMKVReader) SkipContainer() (err error) {
	// Container [
	//   len: int,
	//   data: variant
	// ]
	len, err := p.ReadInt()
	if err != nil {
		return err
	}

	p.offset += int64(len)
	buff := make([]byte, len)
	p.reader.Read(buff) // discard data
	return nil
}
