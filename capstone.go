package capstone

/*
#cgo CFLAGS: -I./third_party/capstone/include/capstone
#cgo LDFLAGS: -L./third_party/capstone -lcapstone
#include <capstone.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// disassembly modes; big/little endian, 16/32/64 bit
type ModeId C.uint

const (
	MODE_LE_16 = ModeId(C.CS_MODE_LITTLE_ENDIAN & C.CS_MODE_16)
	MODE_LE_32 = ModeId(C.CS_MODE_LITTLE_ENDIAN & C.CS_MODE_32)
	MODE_LE_64 = ModeId(C.CS_MODE_LITTLE_ENDIAN & C.CS_MODE_64)
	MODE_BE_16 = ModeId(C.CS_MODE_BIG_ENDIAN & C.CS_MODE_16)
	MODE_BE_32 = ModeId(C.CS_MODE_BIG_ENDIAN & C.CS_MODE_32)
	MODE_BE_64 = ModeId(C.CS_MODE_BIG_ENDIAN & C.CS_MODE_64)
)

// cross architecture instruction groups
type GrpId C.uchar

const (
	GRP_INVALID = GrpId(C.CS_GRP_INVALID)
	GRP_JMP     = GrpId(C.CS_GRP_JUMP)
	GRP_CALL    = GrpId(C.CS_GRP_CALL)
	GRP_RET     = GrpId(C.CS_GRP_RET)
	GRP_INT     = GrpId(C.CS_GRP_INT)
	GRP_IRET    = GrpId(C.CS_GRP_IRET) // ??
)

// cross architecture operand types
type OpTypeId C.uint

const (
	OP_INVALID = OpTypeId(C.CS_OP_INVALID)
	OP_REG     = OpTypeId(C.CS_OP_REG) // register
	OP_IMM     = OpTypeId(C.CS_OP_IMM) // immediate
	OP_MEM     = OpTypeId(C.CS_OP_MEM) // memory
	OP_FP      = OpTypeId(C.CS_OP_FP)  // float
)

func strerror(errno C.cs_err) error {
	msg := "Capstone: %s"
	err := C.GoString(C.cs_strerror(errno))
	return fmt.Errorf(msg, err)
}

type Capstone struct {
	// limit disassembly to N instructions
	DisasmLimit int
	// don't fill instruction detail struct
	NoDetail bool
	// libcapstone handle
	handle C.csh
	insn   *C.cs_insn
	count  C.ulong
}

func (cs *Capstone) open(arch C.cs_arch, mode C.cs_mode) error {
	err := C.cs_open(arch, mode, &cs.handle)
	if err != 0 {
		return strerror(err)
	}
	if !cs.NoDetail {
		err = C.cs_option(cs.handle, C.CS_OPT_DETAIL, C.CS_OPT_ON)
		if err != 0 {
			return strerror(err)
		}
	}
	return nil
}

// should defer Close()
func New(mode ModeId) (*Capstone, error) {
	cs := Capstone{}
	err := cs.open(C.cs_arch(arch), C.cs_mode(mode))
	if err != nil {
		return nil, err
	}
	return &cs, nil
}

func (cs *Capstone) Close() {
	if cs.insn != nil {
		C.cs_free(cs.insn, cs.count)
	}
	C.cs_close(&cs.handle)
}

// cs_disasm wrapper
func (cs *Capstone) Disasseble(data []byte, entry uint64) ([]Instruction, error) {
	if cs.insn != nil {
		C.cs_free(cs.insn, cs.count) // cleanup old disasm if existent
	}
	addr := (*C.uchar)(unsafe.Pointer(&data[0])) // C.CBytes(data) /wo copy + /wo GC
	length := C.ulong(len(data))
	c_entry := C.ulong(entry)
	limit := C.ulong(cs.DisasmLimit)

	// TODO: cs_disasm_iter is said to be 30% faster
	n := C.cs_disasm(cs.handle, addr, length, c_entry, limit, &cs.insn)
	if err := C.cs_errno(cs.handle); err != 0 {
		return nil, strerror(err)
	}

	return newInstructionArray(cs.insn, n), nil
}
