package capstone

/*
A block shall be a sequence of instructions terminated by an unconditional jump
or a return instruction.
*/
type Block []*Instruction

// Parse blocks from an instruction sequence
func NewBlocks(is []Instruction) []Block {
	blks := parseBlocks(is)
	return blks
}

var BlockSeparatorInstructions = []InsId{INS_JMP}
var BlockSeparatorGroups = []GrpId{GRP_RET}

func parseBlocks(insns []Instruction) []Block {
	blks := []Block{}
	curr := Block{}

	nextblk := func() {
		blks = append(blks, curr)
		curr = Block{}
	}

	for _, i := range insns {
		for _, id := range BlockSeparatorInstructions {
			if i.Is(id) {
				nextblk()
			}
		}
		for _, grp := range BlockSeparatorGroups {
			if i.InGroup(grp) {
				nextblk()
			}
		}

		curr = append(curr, &i)
	}

	return blks
}

func (b Block) Len() int { return len(b) }
