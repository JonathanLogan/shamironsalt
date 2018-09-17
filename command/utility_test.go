package command

import (
	"bytes"
	"os"
	"strconv"
	"testing"
	"time"
)

func Test_WriteFile(t *testing.T) {
	data := []byte("Test data")
	file := "/tmp/shamironsalt.test.write." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	err := WriteFile(file, data)
	if err != nil {
		t.Errorf("Error writing to file: %s", err)
	}
	err = WriteFile(file, data)
	if err == nil {
		t.Errorf("May not write to existing file")
	}
}

func Test_ReadFile(t *testing.T) {
	data := []byte("Test data")
	file := "/tmp/shamironsalt.test.read." + strconv.Itoa(int(time.Now().Unix()))
	defer os.Remove(file)
	err := WriteFile(file, data)
	if err != nil {
		t.Errorf("Error writing to file: %s", err)
	}
	datar, err := ReadFile(file + "x")
	if err == nil {
		t.Errorf("May not read from non-existing file")
	}
	datar, err = ReadFile(file)
	if err != nil {
		t.Errorf("Read error: %s", err)
	}
	if !bytes.Equal(data, datar) {
		t.Error("Read data does not match written data")
	}
}

// func Test_PrintError(t *testing.T) {
// 	PrintError("%s %s\n", "Ignore", "this error")
// }
