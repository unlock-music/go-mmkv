package go_mmkv

import (
	"encoding/binary"
	"fmt"
	"io"
)

type MMKVInfo struct {
	CRC32          uint32
	Version        uint32
	Sequence       uint32
	IV             [16]byte
	ActualSize     uint32
	LastActualSize uint32
	LastCRCDigest  uint32
	Flags          uint64
}

const mmkvMetaSize = 0x70

type MMKVReader struct {
	reader io.Reader
	offset int64
	size   int64
	Info   *MMKVInfo
}

func readU32LE(reader io.Reader) (uint32, error) {
	buf := make([]byte, 4)
	_, err := reader.Read(buf)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf), nil
}

func readMeta(reader io.Reader) (*MMKVInfo, error) {
	buf := make([]byte, mmkvMetaSize)
	n, err := reader.Read(buf)
	if err != nil {
		return nil, err
	}
	if n != len(buf) {
		return nil, fmt.Errorf("go-mmkv: metadata read EOF: got %d bytes, expected %d bytes", n, len(buf))
	}

	info := &MMKVInfo{
		CRC32:          binary.LittleEndian.Uint32(buf[0x00:0x04]),
		Version:        binary.LittleEndian.Uint32(buf[0x04:0x08]),
		Sequence:       binary.LittleEndian.Uint32(buf[0x08:0x0C]),
		IV:             [16]byte(buf[0x0C:0x1C]),
		ActualSize:     binary.LittleEndian.Uint32(buf[0x1C:0x20]),
		LastActualSize: binary.LittleEndian.Uint32(buf[0x20:0x24]),
		LastCRCDigest:  binary.LittleEndian.Uint32(buf[0x24:0x28]),
		Flags:          binary.LittleEndian.Uint64(buf[0x68:0x70]),
	}
	return info, nil
}

// NewMMKVReader opens an MMKV data stream.
// crc may be nil for plaintext; password decrypts with AES-128-CFB using IV from crc.
func NewMMKVReader(source io.Reader, maxReadSize int64, password []byte, crc io.Reader) (r *MMKVReader, err error) {
	actualSize, err := readU32LE(source)
	if err != nil {
		return nil, fmt.Errorf("go-mmkv: failed to read actual size from mmkv: %v", err)
	}

	// Crypto MMKV: Requires CRC file to be present.
	var meta *MMKVInfo
	if crc != nil {
		meta, err = readMeta(crc)
		if err != nil {
			return nil, err
		}

		// Wrap with crypto reader when password is provided
		if password != nil {
			if source, err = NewMMKVCrypto(source, password, meta.IV[:]); err != nil {
				return nil, fmt.Errorf("NewMMKVParser: init crypto fail: %v", err)
			}
		}
		actualSize = meta.ActualSize
	}

	size := int64(actualSize) + 4
	if maxReadSize >= 0 {
		size = min(size, maxReadSize)
	}

	r = &MMKVReader{
		reader: source,
		offset: 4,
		size:   size,
		Info:   meta,
	}
	_, err = r.ReadInt()
	return r, err
}

func (p *MMKVReader) BytesAvailable() int64 {
	return p.size - p.offset
}

func (p *MMKVReader) IsEOF() bool {
	return p.BytesAvailable() <= 0
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
	if err != nil || len == 0 {
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
	if err != nil || len == 0 {
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

	// empty container? skip
	if container_len == 0 {
		return "", nil
	}

	expectedOffset := p.offset + int64(container_len)
	value, bytesRead, err := p.ReadStringSafe(container_len)
	if err != nil {
		return "", fmt.Errorf("ReadStringValue: could not safely read container: %v", err)
	}
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
