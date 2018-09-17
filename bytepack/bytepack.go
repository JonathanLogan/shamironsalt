// Package bytepack implements binary storage of byte slices including length annotation and
// a marker to identify the field
package bytepack

import (
	"errors"
)

var (
	// ErrIntTooLong is returned when an int > 24bit is to be encoded
	ErrIntTooLong = errors.New("bytepack: int too long")
	// ErrFieldTooShort is returned when any byte slice cannot contain the value looked for
	ErrFieldTooShort = errors.New("bytepack: field too short")
	// ErrFieldCorrupt is returned if the annotation does not describe the field (the field is too short)
	ErrFieldCorrupt = errors.New("bytepack: field corrupt")
	// ErrDuplicateField is returned if multiple fields of the same type are encoded in a byteslice
	ErrDuplicateField = errors.New("bytepack: multiple fields of same marker")
)

// Itob converts an int to a byte slice. Maximum 24bit
func Itob(i int) ([]byte, error) {
	rb := make([]byte, 3)
	if i > 16777215 {
		return nil, ErrIntTooLong
	}
	rb[0] = byte(i % 256)
	rb[1] = byte((i / 256) % 256)
	rb[2] = byte((i / 65536) % 256)
	return rb, nil
}

// Btoi converts 24bits byte slice into int.
func Btoi(b []byte) (int, error) {
	if len(b) < 3 {
		return 0, ErrFieldTooShort
	}
	return int(b[0]) + int(b[1])*256 + int(b[2])*65536, nil
}

// Pack appends d to b including field marker and length
func Pack(b, d []byte, marker int) ([]byte, error) {
	m, err := Itob(marker)
	if err != nil {
		return b, err
	}
	l, err := Itob(len(d))
	if err != nil {
		return b, err
	}
	b = append(b, m...)
	b = append(b, l...)
	b = append(b, d...)
	return b, nil
}

// Unpack parses b to return the marker and the field content. It returns b shortened by the field
func Unpack(b []byte) (field, shortb []byte, marker int, err error) {
	if len(b) < 7 { // No space for any field
		err = ErrFieldTooShort
		return
	}
	marker, err = Btoi(b[0:3])
	if err != nil {
		return
	}
	length, err := Btoi(b[3:6])
	if err != nil {
		return
	}
	if len(b) < length+6 {
		err = ErrFieldCorrupt
		return
	}
	field = b[6 : 6+length]
	shortb = b[6+length:]
	return
}

// UnpackAll parses b and returns a map of fields contained
func UnpackAll(b []byte) (fields map[int][]byte, err error) {
	var f []byte
	var m int
	fields = make(map[int][]byte)
	for len(b) > 0 {
		f, b, m, err = Unpack(b)
		if err != nil {
			return
		}
		if _, exists := fields[m]; exists {
			err = ErrDuplicateField
			return
		}
		fields[m] = f
	}
	return
}

// VerifyFields checks if all fields are present
func VerifyFields(myMap map[int][]byte, fields []int) bool {
	for _, k := range fields {
		if _, exists := myMap[k]; !exists {
			return false
		}
	}
	return true
}
