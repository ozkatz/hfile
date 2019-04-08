// Copyright (C) 2015 Foursquare Labs Inc.

package hfile

import (
	"bytes"
	"encoding/binary"
)

type Scanner struct {
	reader *Reader
	idx    int
	block  []byte
	pos    *int
	buf    []byte

	// When off, maybe be faster but may return incorrect results rather than error on out-of-order keys.
	EnforceKeyOrder bool
	OrderedOps
}

func NewScanner(r *Reader) *Scanner {
	var buf []byte
	if r.CompressionCodec > CompressionNone {
		buf = make([]byte, int(float64(r.TotalUncompressedDataBytes/uint64(len(r.index)))*1.5))
	}
	return &Scanner{r, 0, nil, nil, buf, true, OrderedOps{nil}}
}

func (s *Scanner) Reset() {
	s.idx = 0
	s.block = nil
	s.pos = nil
	s.ResetState()
}

func (s *Scanner) blockFor(key []byte) ([]byte, error, bool) {
	if s.EnforceKeyOrder {
		err := s.CheckIfKeyOutOfOrder(key)
		if err != nil {
			return nil, err, false
		}
	}

	if s.reader.index[s.idx].IsAfter(key) {
		return nil, nil, false
	}

	idx := s.reader.FindBlock(s.idx, key)

	if idx != s.idx || s.block == nil { // need to load a new block
		data, err := s.reader.GetBlockBuf(idx, s.buf)
		if err != nil {
			return nil, err, false
		}
		i := 8
		s.pos = &i
		s.idx = idx
		s.block = data
	}

	return s.block, nil, true
}

func (s *Scanner) GetFirst(key []byte) ([]byte, error, bool) {
	data, err, ok := s.blockFor(key)
	if !ok {
		return nil, err, ok
	}
	value, _, found := s.getValuesFromBuffer(data, s.pos, key, true)
	return value, nil, found
}

func (s *Scanner) GetAll(key []byte) ([][]byte, error) {
	data, err, ok := s.blockFor(key)

	if !ok {
		return nil, err
	}

	_, found, _ := s.getValuesFromBuffer(data, s.pos, key, false)
	return found, err
}

func (s *Scanner) getValuesFromBuffer(buf []byte, pos *int, key []byte, first bool) ([]byte, [][]byte, bool) {
	var acc [][]byte

	i := *pos

	for len(buf)-i > 8 {
		keyLen := int(binary.BigEndian.Uint32(buf[i : i+4]))
		valLen := int(binary.BigEndian.Uint32(buf[i+4 : i+8]))

		cmp := bytes.Compare(buf[i+8:i+8+keyLen], key)

		switch {
		case cmp == 0:
			i += 8 + keyLen

			ret := make([]byte, valLen)
			copy(ret, buf[i:i+valLen])

			i += valLen // now on next length pair

			if first {
				*pos = i
				return ret, nil, true
			}
			acc = append(acc, ret)
		case cmp > 0:
			*pos = i
			return nil, acc, len(acc) > 0
		default:
			i += 8 + keyLen + valLen
		}
	}

	*pos = i
	return nil, acc, len(acc) > 0
}

func (s *Scanner) Release() {
	s.Reset()
	select {
	case s.reader.scannerCache <- s:
	default:
	}
}
