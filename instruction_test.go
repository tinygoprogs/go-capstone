package capstone

import (
	"fmt"
	"math"
	"testing"
)

func TestInstructionJmpOpStr(t *testing.T) {
	cs, err := New(MODE_LE_64)
	if err != nil {
		t.Error("New")
	}
	defer cs.Close()

	entry := uint64(0x4000000)
	if entry > math.MaxInt32 {
		t.Error("IMM conversion requires smaller entry point")
	}
	op_ex := int32(uint32(entry) + uint32(0x11223344))

	// jmp near 0x11223344
	code := []byte{0xe9, 0x3f, 0x33, 0x22, 0x11}
	is, err := cs.Disasseble(code, entry)
	i := is[0]

	opstr := i.Mnemonic() + " " + i.OpStr()
	opstr_ex := fmt.Sprintf("jmp 0x%x", op_ex)
	if opstr != opstr_ex {
		t.Errorf("op str expected '%s', got '%s'", opstr_ex, opstr)
	}

	dtl, err := i.Detail()
	if err != nil {
		t.Error("Detail")
	}

	op_n := dtl.OpCount()
	op_n_ex := 1
	if op_n != op_n_ex {
		t.Errorf("op count expected '%d', got '%d'", op_n_ex, op_n)
	}

	op_sz := dtl.OpSize(0)
	op_sz_ex := uint8(4)
	if op_sz != op_sz_ex {
		t.Errorf("op size expected '%d', got '%d': %#v", op_sz_ex, op_sz, i.Bytes())
	}

	op_t := dtl.OpTypes()[0]
	op_t_ex := OP_IMM
	if op_t != op_t_ex {
		t.Errorf("op type expected '%d', got '%d'", op_t_ex, op_t)
	}

	tmp := dtl.Ops()[0]
	t.Logf("tmp=%#v", tmp)
	op, ok := tmp.(int32)
	if !ok {
		t.Error("type assertion failed, operand must be IMM")
	}

	if op != op_ex {
		t.Errorf("operand expected '%x', got '%x'", op_ex, op)
	}
}

type opSzInfo struct {
	code     []byte
	mnem     string
	entry    uint64
	op_sz_ex uint8
}

func TestInstructionOpSizes(t *testing.T) {
	cs, err := New(MODE_LE_64)
	if err != nil {
		t.Error("New")
	}
	defer cs.Close()

	tests := []opSzInfo{
		// instruction bytes, mnemonic, entry, expected immediate operand size
		{[]byte{0xeb, 0x31}, "jmp near 0x33", 0, 1},
		{[]byte{0xe8, 0x70, 0xfb, 0xff, 0xff}, "jmp 0x2310", 0x279b, 4},
		{[]byte{0x0f, 0x84, 0x84, 0x00, 0x00, 0x00}, "je 138", 0, 4},
	}
	for _, test := range tests {
		is, _ := cs.Disasseble(test.code, test.entry)
		i := is[0]
		d, _ := i.Detail()
		op_sz := d.OpSize(0)
		if op_sz != test.op_sz_ex {
			t.Errorf("op size expected '%d', got '%d' from '%s' @ 0x%x",
				test.op_sz_ex, op_sz, test.mnem, test.entry)
		}
	}
}
