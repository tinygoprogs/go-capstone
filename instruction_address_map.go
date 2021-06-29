package capstone

type IAddrMap map[uint64]*Instruction

func NewIAddrMap(ia []Instruction) *IAddrMap {
	m := IAddrMap{}

	for _, i := range ia {
		m[i.Addr()] = &i
	}

	return &m
}
