package capstone

import (
	"testing"
	"unsafe"
)

func TestDisassembleJmpRax(t *testing.T) {
	cs, err := New(MODE_LE_64)
	if err != nil {
		t.Error("New")
	}
	defer cs.Close()

	code := []byte{0xff, 0xe0}
	entry := uint64(0)
	is, err := cs.Disasseble(code, entry)
	if err != nil {
		t.Error("Disasseble")
	}

	jmprax := is[0]
	mnem := jmprax.Mnemonic()
	mnem_ex := "jmp"
	if mnem != mnem_ex {
		t.Errorf("'%s' != '%s'", mnem, mnem_ex)
	}

	dtl := jmprax.detail
	if uintptr(unsafe.Pointer(dtl)) == 0 {
		t.Error("detail is NULL")
	}

	if !jmprax.InGroup(GRP_JMP) {
		t.Error("not in group GRP_JMP")
	}
}
