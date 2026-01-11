// Package introspect provides stack introspection using DWARF debug information.
// It allows printing local variables of the current stack and all parent call frames.
package introspect

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"runtime"
	"unsafe"
)

// Global file handles to keep DWARF data accessible
var machoFile *macho.File
var elfFile *elf.File

// aslrOffset is the difference between runtime and DWARF addresses
var aslrOffset int64

// dwarfData caches the loaded DWARF data
var dwarfData *dwarf.Data

// HasDWARFInfo checks if the current binary contains DWARF debug information.
func HasDWARFInfo() (bool, error) {
	execPath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("getting executable path: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		f, err := macho.Open(execPath)
		if err != nil {
			return false, fmt.Errorf("opening macho: %w", err)
		}
		defer f.Close()

		dwarfData, err := f.DWARF()
		if err != nil {
			return false, nil
		}
		reader := dwarfData.Reader()
		entry, err := reader.Next()
		return entry != nil && err == nil, nil

	case "linux":
		f, err := elf.Open(execPath)
		if err != nil {
			return false, fmt.Errorf("opening elf: %w", err)
		}
		defer f.Close()

		dwarfData, err := f.DWARF()
		if err != nil {
			return false, nil
		}
		reader := dwarfData.Reader()
		entry, err := reader.Next()
		return entry != nil && err == nil, nil

	default:
		return false, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

func loadDWARF() (*dwarf.Data, error) {
	if dwarfData != nil {
		return dwarfData, nil
	}

	execPath, err := os.Executable()
	if err != nil {
		return nil, err
	}

	switch runtime.GOOS {
	case "darwin":
		f, err := macho.Open(execPath)
		if err != nil {
			return nil, err
		}
		machoFile = f // Keep file open for DWARF data access
		dwarfData, err = f.DWARF()
		return dwarfData, err

	case "linux":
		f, err := elf.Open(execPath)
		if err != nil {
			return nil, err
		}
		elfFile = f // Keep file open for DWARF data access
		dwarfData, err = f.DWARF()
		return dwarfData, err

	default:
		return nil, fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// calculateASLROffset finds the difference between runtime and DWARF addresses
// using the PrintStackVariables function itself as a reference point
func calculateASLROffset(d *dwarf.Data) {
	// Get the PC of this function from runtime
	pc, _, _, ok := runtime.Caller(0)
	if !ok {
		return
	}

	// Find the function name for this PC
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return
	}
	funcName := fn.Name()
	entryPC := fn.Entry()

	// Find the same function in DWARF
	reader := d.Reader()
	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}
		if entry.Tag == dwarf.TagSubprogram {
			name, _ := entry.Val(dwarf.AttrName).(string)
			if name == funcName {
				lowPC, ok := entry.Val(dwarf.AttrLowpc).(uint64)
				if ok {
					aslrOffset = int64(entryPC) - int64(lowPC)
					return
				}
			}
		}
	}
}

// variableInfo holds information about a variable from DWARF
type variableInfo struct {
	name     string
	location []byte
	typeRef  dwarf.Offset
}

// findFunctionAndVariables finds the function containing the given PC and returns its variables
func findFunctionAndVariables(d *dwarf.Data, pc uint64) (funcName string, vars []variableInfo, frameBaseLoc []byte) {
	reader := d.Reader()

	for {
		entry, err := reader.Next()
		if err != nil || entry == nil {
			break
		}

		if entry.Tag == dwarf.TagSubprogram {
			lowPC, hasLow := entry.Val(dwarf.AttrLowpc).(uint64)

			var highPC uint64
			var hasHigh bool
			if h, ok := entry.Val(dwarf.AttrHighpc).(uint64); ok {
				highPC = h
				hasHigh = true
			} else if h, ok := entry.Val(dwarf.AttrHighpc).(int64); ok {
				highPC = lowPC + uint64(h)
				hasHigh = true
			}

			if hasLow && hasHigh {
				if highPC < lowPC {
					highPC = lowPC + highPC
				}

				if pc >= lowPC && pc <= highPC {
					if name, ok := entry.Val(dwarf.AttrName).(string); ok {
						funcName = name
					}

					if fb, ok := entry.Val(dwarf.AttrFrameBase).([]byte); ok {
						frameBaseLoc = fb
					}

					if entry.Children {
						for {
							child, err := reader.Next()
							if err != nil || child == nil {
								break
							}
							if child.Tag == 0 {
								break
							}

							if child.Tag == dwarf.TagVariable || child.Tag == dwarf.TagFormalParameter {
								vi := variableInfo{}
								if name, ok := child.Val(dwarf.AttrName).(string); ok {
									vi.name = name
								}
								if loc, ok := child.Val(dwarf.AttrLocation).([]byte); ok {
									vi.location = loc
								}
								if typeRef, ok := child.Val(dwarf.AttrType).(dwarf.Offset); ok {
									vi.typeRef = typeRef
								}
								if vi.name != "" && len(vi.location) > 0 {
									vars = append(vars, vi)
								}
							}

							if child.Children {
								reader.SkipChildren()
							}
						}
					}
					return
				}
			}
		}
	}
	return
}

// resolveTypeName looks up the type name from a DWARF type reference
func resolveTypeName(d *dwarf.Data, typeRef dwarf.Offset) string {
	reader := d.Reader()
	reader.Seek(typeRef)

	entry, err := reader.Next()
	if err != nil || entry == nil {
		return "unknown"
	}

	if name, ok := entry.Val(dwarf.AttrName).(string); ok {
		return name
	}

	if entry.Tag == dwarf.TagPointerType {
		if underlyingRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
			return "*" + resolveTypeName(d, underlyingRef)
		}
		return "*unknown"
	}

	switch entry.Tag {
	case dwarf.TagArrayType:
		return "[]..."
	case dwarf.TagStructType:
		return "struct{...}"
	case dwarf.TagSubroutineType:
		return "func(...)"
	}

	return "unknown"
}

// evaluateLocation evaluates a simple DWARF location expression
func evaluateLocation(loc []byte) (offset int64, isFbreg bool) {
	if len(loc) == 0 {
		return 0, false
	}

	// DW_OP_fbreg = 0x91
	if loc[0] == 0x91 {
		offset, _ = decodeSLEB128(loc[1:])
		return offset, true
	}

	return 0, false
}

// decodeSLEB128 decodes a signed LEB128 value
func decodeSLEB128(data []byte) (int64, int) {
	var result int64
	var shift uint
	var bytesRead int

	for i, b := range data {
		bytesRead = i + 1
		result |= int64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			if shift < 64 && (b&0x40) != 0 {
				result |= -(1 << shift)
			}
			break
		}
	}

	return result, bytesRead
}

// evaluateFrameBase evaluates the frame base location expression
func evaluateFrameBase(loc []byte, bp uintptr) uintptr {
	if len(loc) == 0 {
		return bp
	}

	// DW_OP_call_frame_cfa = 0x9c
	// Based on empirical testing, Go on ARM64 uses CFA = BP + 48
	if loc[0] == 0x9c {
		return bp + 48
	}

	// DW_OP_reg6 = 0x56 (rbp on amd64)
	if loc[0] == 0x56 {
		return bp
	}

	// DW_OP_breg6 = 0x76 (rbp + offset on amd64)
	if loc[0] == 0x76 && len(loc) > 1 {
		offset, _ := decodeSLEB128(loc[1:])
		return uintptr(int64(bp) + offset)
	}

	// DW_OP_breg29 = 0x8d (X29/FP + offset on ARM64)
	if loc[0] == 0x8d && len(loc) > 1 {
		offset, _ := decodeSLEB128(loc[1:])
		return uintptr(int64(bp) + offset)
	}

	return bp
}

// readValueAtAddress reads a value at the given address and formats it based on type
func readValueAtAddress(addr uintptr, typeName string) string {
	defer func() {
		if r := recover(); r != nil {
			// Ignore panics from bad memory access
		}
	}()

	switch typeName {
	case "int", "int64":
		val := *(*int64)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "int32":
		val := *(*int32)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "int16":
		val := *(*int16)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "int8":
		val := *(*int8)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "uint", "uint64", "uintptr":
		val := *(*uint64)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "uint32":
		val := *(*uint32)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "uint16":
		val := *(*uint16)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "uint8", "byte":
		val := *(*uint8)(unsafe.Pointer(addr))
		return fmt.Sprintf("%d", val)
	case "float32":
		val := *(*float32)(unsafe.Pointer(addr))
		return fmt.Sprintf("%f", val)
	case "float64":
		val := *(*float64)(unsafe.Pointer(addr))
		return fmt.Sprintf("%f", val)
	case "bool":
		val := *(*bool)(unsafe.Pointer(addr))
		return fmt.Sprintf("%t", val)
	case "string":
		type stringHeader struct {
			Data uintptr
			Len  int
		}
		hdr := *(*stringHeader)(unsafe.Pointer(addr))
		if hdr.Len > 0 && hdr.Len < 1024 && hdr.Data != 0 {
			bytes := make([]byte, hdr.Len)
			for i := 0; i < hdr.Len; i++ {
				bytes[i] = *(*byte)(unsafe.Pointer(hdr.Data + uintptr(i)))
			}
			return fmt.Sprintf("%q", string(bytes))
		}
		return `""`
	default:
		if len(typeName) > 0 && typeName[0] == '*' {
			val := *(*uintptr)(unsafe.Pointer(addr))
			return fmt.Sprintf("0x%x", val)
		}
		bytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			bytes[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
		}
		return fmt.Sprintf("0x%x", binary.LittleEndian.Uint64(bytes))
	}
}

// getFramePointers returns the base pointers for each frame in the call stack
func getFramePointers(skip int) []uintptr {
	var pcs [50]uintptr
	n := runtime.Callers(skip+1, pcs[:])

	bps := make([]uintptr, n)

	bp := getBasePointer()

	// Skip frames to align with runtime.Callers
	for i := 0; i < skip+1 && bp != 0; i++ {
		bp = *(*uintptr)(unsafe.Pointer(bp))
	}

	for i := 0; i < n && bp != 0; i++ {
		bps[i] = bp
		bp = *(*uintptr)(unsafe.Pointer(bp))
	}

	return bps
}

// getBasePointer returns the current base pointer (RBP on amd64, X29 on arm64)
//
//go:noinline
func getBasePointer() uintptr

// PrintStackVariables prints local variables for the current stack and all parent frames.
// It writes output to stdout.
//
//go:noinline
func PrintStackVariables() {
	FprintStackVariables(os.Stdout)
}

// FprintStackVariables prints local variables for the current stack and all parent frames
// to the specified writer.
//
//go:noinline
func FprintStackVariables(w io.Writer) {
	d, err := loadDWARF()
	if err != nil {
		fmt.Fprintf(w, "Error loading DWARF: %v\n", err)
		return
	}

	// Calculate ASLR offset
	calculateASLROffset(d)

	// Get the call stack PCs (skip Callers, FprintStackVariables, and PrintStackVariables if called)
	var pcs [50]uintptr
	n := runtime.Callers(3, pcs[:])

	// Get frame pointers
	bps := getFramePointers(3)

	frames := runtime.CallersFrames(pcs[:n])

	frameIdx := 0
	for {
		frame, more := frames.Next()

		fmt.Fprintf(w, "\n=== Frame %d: %s ===\n", frameIdx, frame.Function)
		fmt.Fprintf(w, "    %s:%d\n", frame.File, frame.Line)

		dwarfPC := uint64(int64(frame.PC) - aslrOffset)

		funcName, vars, frameBaseLoc := findFunctionAndVariables(d, dwarfPC)

		if funcName == "" {
			fmt.Fprintf(w, "    (no DWARF info for this frame)\n")
		} else if len(vars) == 0 {
			fmt.Fprintf(w, "    (no variables)\n")
		} else {
			var frameBase uintptr
			if frameIdx < len(bps) && bps[frameIdx] != 0 {
				frameBase = evaluateFrameBase(frameBaseLoc, bps[frameIdx])
			}

			fmt.Fprintf(w, "    Variables:\n")
			for _, v := range vars {
				typeName := resolveTypeName(d, v.typeRef)
				offset, isFbreg := evaluateLocation(v.location)

				if isFbreg && frameBase != 0 {
					addr := uintptr(int64(frameBase) + offset)
					value := readValueAtAddress(addr, typeName)
					fmt.Fprintf(w, "      %s (%s) = %s\n", v.name, typeName, value)
				} else {
					fmt.Fprintf(w, "      %s (%s) = <location unavailable>\n", v.name, typeName)
				}
			}
		}

		frameIdx++
		if !more {
			break
		}
	}
}
