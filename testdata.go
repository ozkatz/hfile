// Copyright (C) 2015 Foursquare Labs Inc.

package hfile

import (
	"encoding/binary"
	"fmt"
)

func MockKeyInt(i int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}

func MockValueForMockKey(key []byte) []byte {
	return MockValueInt(int(binary.BigEndian.Uint32(key)))
}

func MockValueInt(i int) []byte {
	return []byte(fmt.Sprintf("value-for-%d", i))
}
func MockMultiValueInt(i, k int) []byte {
	return []byte(fmt.Sprintf("value-for-%d-%d", i, k))
}

func GenerateMockHfile(path string, keyCount, blockSize int, compress, progress bool) error {
	w, err := NewLocalWriter(path, compress, blockSize)
	if err != nil {
		return err
	}
	return WriteMockIntPairs(w, keyCount, progress, false)
}

func GenerateMockMultiHfile(path string, keyCount, blockSize int, compress, progress bool) error {
	w, err := NewLocalWriter(path, compress, blockSize)
	if err != nil {
		return err
	}
	return WriteMockIntPairs(w, keyCount, progress, true)
}

func WriteMockIntPairs(w *Writer, keyCount int, progress bool, multi bool) error {
	for i := 0; i < keyCount; i++ {
		if progress && i%10000 == 0 {
			fmt.Printf("\r %d %.02f%%", i, (float64(i)*100.0)/float64(keyCount))
		}
		if multi && i%2 == 1 {
			for k := 0; k < 3; k++ {
				if err := w.Write(MockKeyInt(i), MockMultiValueInt(i, k)); err != nil {
					return err
				}
			}
		} else {
			if err := w.Write(MockKeyInt(i), MockValueInt(i)); err != nil {
				return err
			}
		}
	}

	if progress {
		fmt.Println()
	}

	w.Close()
	return nil
}
