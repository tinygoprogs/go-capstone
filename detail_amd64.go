package capstone

/*
#cgo CFLAGS: -I./third_party/capstone/include/capstone
#cgo LDFLAGS: -L./third_party/capstone -lcapstone
#include <capstone.h>

// access anonymous union..
cs_x86* get_x86(cs_detail* dtl) { return &dtl->x86; }

// access field name 'type', which is a keyword in golang..
x86_op_type get_x86_op_type(cs_x86_op* op) { return op->type; }

// more anonymous unions ..
x86_reg op_get_reg(cs_x86_op* op) { return op->reg; }
int64_t op_get_imm(cs_x86_op* op) { return op->imm; }
x86_op_mem op_get_mem(cs_x86_op* op) { return op->mem; }

*/
import "C"
import (
	"fmt"
	"log"
	"unsafe"
)

type Detail struct {
	generic *C.cs_detail
	arch    *C.cs_x86
	insn    *Instruction // shitty imm op-size workaround
}

func NewDetail(i *Instruction) (*Detail, error) {
	if uintptr(unsafe.Pointer(i.detail)) == 0 {
		return nil, fmt.Errorf("no detail available")
	}
	dtl := Detail{
		generic: i.detail,
		insn:    i,
	}
	dtl.arch = C.get_x86(dtl.generic)
	return &dtl, nil
}

func (d *Detail) OpCount() int {
	return int(d.arch.op_count)
}

// Remeber: 1 byte immeadiate operand size does NOT mean 0x100 possibilities!
// TODO calculate bounds
func (d *Detail) OpSize(n int) uint8 {
	if int(d.arch.op_count) <= n {
		log.Printf("warning: operand count < requested operand")
		return uint8(0)
	}

	// XXX maybe check for jmp/call instruction, otherwise return default or 0
	sz := uint8(d.insn.size)
	if uint(d.arch.op_count) == 1 {
		switch sz {
		case 2, 5:
			return sz - 1
		case 6, 7, 8:
			return 4
		default:
			break
		}
	}
	return 8

	/* FIXME: suck that
	return uint8(d.arch.operands[C.int(n)].size)
	*/
}

func (d *Detail) OpTypes() []OpTypeId {
	opids := []OpTypeId{}

	for i := C.uchar(0); i < d.arch.op_count; i++ {
		opids = append(opids, OpTypeId(C.get_x86_op_type(&d.arch.operands[i])))
	}

	return opids
}

// this sux: fix golang's inability to access anonymous unions
func (d *Detail) Ops() []interface{} {
	ops := []interface{}{}
	var nop interface{}

	for i, op_t := range d.OpTypes() {
		opi := &d.arch.operands[i]
		valid := true

		switch op_t {
		case OP_IMM:
			nop = uint64(C.op_get_imm(opi))
		case OP_MEM:
			nop = C.op_get_mem(opi) // struct
		case OP_REG:
			nop = uint64(C.op_get_reg(opi))
		case OP_INVALID:
			log.Printf("invalid operand")
			valid = false
		default:
			log.Printf("unknown operand")
			valid = false
		}

		if !valid {
			continue
		}
		tmp, ok := nop.(uint64)
		if !ok {
			continue
		}
		switch d.OpSize(i) {
		case 1:
			ops = append(ops, *(*int8)(unsafe.Pointer(&tmp)))
		case 2:
			ops = append(ops, *(*int16)(unsafe.Pointer(&tmp)))
		case 4:
			ops = append(ops, *(*int32)(unsafe.Pointer(&tmp)))
		}
	}

	return ops
}
