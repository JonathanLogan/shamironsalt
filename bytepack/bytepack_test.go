package bytepack

import (
	"bytes"
	"testing"
)

func Test_Itob(t *testing.T) {
	for i := 0; i < 16777216; i++ {
		b, err := Itob(i)
		//fmt.Println(b)
		if err != nil {
			t.Errorf("Itob failed for %d: %s", i, err)
		}
		j, err := Btoi(b)
		if err != nil {
			t.Errorf("Btoi failed for: %b, %s", b, err)
		}
		if j != i {
			t.Fatalf("Itob-Btoi failed for %d!=%d", i, j)
		}
	}
	_, err := Itob(16777216)
	if err == nil {
		t.Error("Itob must fail for >=16777216")
	}
	_, err = Btoi([]byte("  "))
	if err == nil {
		t.Error("Btoi must fail for small slices")
	}

}

func Test_Pack(t *testing.T) {
	var b []byte
	marker := int(30)
	field := []byte("Testing")
	d, err := Pack(b, field, marker)
	if err != nil {
		t.Errorf("Packing failed: %s", err)
	}
	fieldU, _, markerU, err := Unpack(d)
	if err != nil {
		t.Errorf("Unpacking failed: %s", err)
	}
	if markerU != marker {
		t.Errorf("Unpack marker failed: %d!=%d", marker, markerU)
	}
	if !bytes.Equal(field, fieldU) {
		t.Errorf("Unpack marker failed: %s!=%s", string(field), string(fieldU))
	}
}

func Test_UnpackAll(t *testing.T) {
	var b []byte
	d, err := Pack(b, []byte("Field1"), 1)
	if err != nil {
		t.Errorf("Packing failed: %s", err)
	}
	d, err = Pack(d, []byte("Field2"), 2)
	if err != nil {
		t.Errorf("Packing failed: %s", err)
	}
	d, err = Pack(d, []byte("Field3"), 3)
	if err != nil {
		t.Errorf("Packing failed: %s", err)
	}
	fields, err := UnpackAll(d)
	if err != nil {
		t.Errorf("Unpacking failed: %s", err)
	}
	d, err = Pack(d, []byte("ErrorField"), 3)
	if err != nil {
		t.Errorf("Packing failed: %s", err)
	}
	fields, err = UnpackAll(d)
	if err == nil {
		t.Error("Unpacking must throw error on duplicate fields")
	}
	_ = fields
}

func Test_VerifyFields(t *testing.T) {
	td := make(map[int][]byte)
	td[0] = []byte("ab")
	td[1] = []byte("ab")
	ok := VerifyFields(td, []int{0, 1})
	if !ok {
		t.Error("Field verification failed when it should work")
	}
	ok = VerifyFields(td, []int{0, 1, 2})
	if ok {
		t.Error("Field verification worked when it should have failed")
	}
}
