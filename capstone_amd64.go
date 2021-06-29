package capstone

/*
#cgo CFLAGS: -I./third_party/capstone/include/capstone
#cgo LDFLAGS: -L./third_party/capstone -lcapstone
#include <capstone.h>
*/
import "C"

// disassembly architecture
type ArchId C.uint

const (
	arch = ArchId(C.CS_ARCH_X86)
)

// archtitecture dependent instructions
type InsId C.uint

const (
	INS_JMP = InsId(C.X86_INS_JMP)
)
