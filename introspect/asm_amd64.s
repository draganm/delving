//go:build amd64

#include "textflag.h"

// func getBasePointer() uintptr
TEXT ·getBasePointer(SB), NOSPLIT, $0-8
    MOVQ BP, ret+0(FP)
    RET
