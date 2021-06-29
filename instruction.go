package capstone

/*
#cgo CFLAGS: -I./third_party/capstone/include/capstone
#cgo LDFLAGS: -L./third_party/capstone -lcapstone
#include <capstone.h>
*/
import "C"
import (
	"unsafe"
	//"fmt"
)

type Instruction C.cs_insn

func (i *Instruction) Addr() uint64 {
	return uint64(i.address)
}

func (i *Instruction) Mnemonic() string {
	return C.GoString((*C.char)(unsafe.Pointer(&i.mnemonic)))
}

func (i *Instruction) OpStr() string {
	return C.GoString((*C.char)(unsafe.Pointer(&i.op_str)))
}

func (i *Instruction) Bytes() []byte {
	return C.GoBytes(unsafe.Pointer(&i.bytes), C.int(i.size))
}

func (i *Instruction) Size() int {
	return int(i.size)
}

func (i *Instruction) Is(id InsId) bool {
	return InsId(i.id) == id
}

func (i *Instruction) Detail() (*Detail, error) {
	return NewDetail(i)
}

func (i *Instruction) InGroup(group GrpId) bool {
	dtl := i.detail
	grp := C.uchar(group)
	//fmt.Printf("%v %v %d\n", &dtl, grp, byte(dtl.groups_count))
	for c := byte(0); c < byte(dtl.groups_count); c++ {
		if dtl.groups[c] == grp {
			return true
		}
	}
	return false
}
