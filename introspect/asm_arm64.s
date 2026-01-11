//go:build arm64

#include "textflag.h"

// func getBasePointer() uintptr
// On ARM64, the frame pointer is FP (X29)
TEXT ·getBasePointer(SB), NOSPLIT, $0-8
    MOVD R29, ret+0(FP)
    RET
