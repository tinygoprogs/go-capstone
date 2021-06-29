/*
We only support disassebly of the target architecture as it is assumed that
libcapstone is compiled only for that architecture.

Opposed to the capstone default, detail is on by default, e.g.:
  cs,_ := New(MODE_64)
  is,_ := cs.Disasseble(code, entrypoint)
  // each instruction is the array 'is' is detailed!
*/
package capstone
