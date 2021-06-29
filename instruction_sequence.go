package capstone

/*
#cgo CFLAGS: -I./third_party/capstone/include/capstone
#cgo LDFLAGS: -L./third_party/capstone -lcapstone
#include <capstone.h>
*/
import "C"
import (
	"reflect"
	"unsafe"
)

// treat the []Instruction slice as constant, memory is managed by C
func newInstructionArray(insn *C.cs_insn, count C.ulong) []Instruction {
	overlay := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(insn)),
		Len:  int(count),
		Cap:  int(count),
	}
	return *(*[]Instruction)(unsafe.Pointer(&overlay))
}

func InsnsBytes(insns []Instruction) []byte {
	tmp := []byte{}
	for _, i := range insns {
		tmp = append(tmp, i.Bytes()...)
	}
	return tmp
}

func InsnsLen(insns []Instruction) int {
	length := 0
	for _, i := range insns {
		length += i.Size()
	}
	return length
}
