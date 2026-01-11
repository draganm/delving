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

// maxDepth is the maximum recursion depth for reading nested values
const maxDepth = 4

// maxSliceElements is the maximum number of slice elements to display
const maxSliceElements = 10

// memberInfo holds information about a struct member from DWARF
type memberInfo struct {
	name    string
	typeRef dwarf.Offset
	offset  int64
}

// getStructMembers reads the members of a struct type from DWARF
func getStructMembers(d *dwarf.Data, typeRef dwarf.Offset) []memberInfo {
	reader := d.Reader()
	reader.Seek(typeRef)

	entry, err := reader.Next()
	if err != nil || entry == nil || entry.Tag != dwarf.TagStructType {
		return nil
	}

	if !entry.Children {
		return nil
	}

	var members []memberInfo
	for {
		child, err := reader.Next()
		if err != nil || child == nil || child.Tag == 0 {
			break
		}

		if child.Tag == dwarf.TagMember {
			mi := memberInfo{}
			if name, ok := child.Val(dwarf.AttrName).(string); ok {
				mi.name = name
			}
			if typeRef, ok := child.Val(dwarf.AttrType).(dwarf.Offset); ok {
				mi.typeRef = typeRef
			}
			// Get member offset - can be int64 or []byte location expression
			if offset, ok := child.Val(dwarf.AttrDataMemberLoc).(int64); ok {
				mi.offset = offset
			} else if locExpr, ok := child.Val(dwarf.AttrDataMemberLoc).([]byte); ok {
				// Simple location expression: DW_OP_plus_uconst
				if len(locExpr) > 0 && locExpr[0] == 0x23 { // DW_OP_plus_uconst
					offset, _ := decodeULEB128(locExpr[1:])
					mi.offset = int64(offset)
				}
			}
			if mi.name != "" {
				members = append(members, mi)
			}
		}

		if child.Children {
			reader.SkipChildren()
		}
	}

	return members
}

// decodeULEB128 decodes an unsigned LEB128 value
func decodeULEB128(data []byte) (uint64, int) {
	var result uint64
	var shift uint
	var bytesRead int

	for i, b := range data {
		bytesRead = i + 1
		result |= uint64(b&0x7f) << shift
		shift += 7
		if b&0x80 == 0 {
			break
		}
	}

	return result, bytesRead
}

// getTypeEntry retrieves a DWARF type entry
func getTypeEntry(d *dwarf.Data, typeRef dwarf.Offset) *dwarf.Entry {
	reader := d.Reader()
	reader.Seek(typeRef)
	entry, err := reader.Next()
	if err != nil {
		return nil
	}
	return entry
}

// getTypeSize gets the byte size of a type from DWARF
func getTypeSize(d *dwarf.Data, typeRef dwarf.Offset) int64 {
	entry := getTypeEntry(d, typeRef)
	if entry == nil {
		return 0
	}
	if size, ok := entry.Val(dwarf.AttrByteSize).(int64); ok {
		return size
	}
	return 0
}

// readValueAtAddress reads a value at the given address using DWARF type information
func readValueAtAddress(d *dwarf.Data, addr uintptr, typeRef dwarf.Offset, depth int) string {
	defer func() {
		if r := recover(); r != nil {
			// Ignore panics from bad memory access
		}
	}()

	if depth > maxDepth {
		return "..."
	}

	entry := getTypeEntry(d, typeRef)
	if entry == nil {
		return "<unknown type>"
	}

	// Get the type name if available
	typeName, _ := entry.Val(dwarf.AttrName).(string)

	// Handle string type early (Go represents strings as struct with str/len fields)
	if typeName == "string" {
		return readStringValue(addr)
	}

	// Handle typedef by following to underlying type
	if entry.Tag == dwarf.TagTypedef {
		// Follow typedef to underlying type
		if underlyingRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
			return readValueAtAddress(d, addr, underlyingRef, depth)
		}
	}

	// Try to handle by type name first (for base types that might have different tags)
	if result := tryReadByTypeName(addr, typeName); result != "" {
		return result
	}

	switch entry.Tag {
	case dwarf.TagSubroutineType:
		return readFuncValue(addr)

	case dwarf.TagPointerType:
		return readPointerValue(d, addr, entry, depth)

	case dwarf.TagStructType:
		// Check if it's a Go string (struct with str/len fields)
		members := getStructMembers(d, typeRef)
		if isStringType(members) {
			return readStringValue(addr)
		}
		// Check if it's a slice (Go slices are structs with specific fields)
		if isSliceType(members) {
			return readSliceValue(d, addr, members, depth)
		}
		return readStructValue(d, addr, typeRef, depth)

	case dwarf.TagArrayType:
		return readArrayValue(d, addr, entry, depth)

	case dwarf.TagBaseType:
		return readPrimitiveValue(d, addr, entry, typeName)

	default:
		// Fall back to type name matching for base types
		return readPrimitiveValue(d, addr, entry, typeName)
	}
}

// tryReadByTypeName attempts to read a value if the type name matches a known primitive
func tryReadByTypeName(addr uintptr, typeName string) string {
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
	}
	return ""
}

// readPointerValue reads a pointer and dereferences it
func readPointerValue(d *dwarf.Data, addr uintptr, entry *dwarf.Entry, depth int) string {
	ptrVal := *(*uintptr)(unsafe.Pointer(addr))

	if ptrVal == 0 {
		return "nil"
	}

	// Get the underlying type
	underlyingRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return fmt.Sprintf("0x%x", ptrVal)
	}

	// Check if this is a pointer to a function
	underlyingEntry := getTypeEntry(d, underlyingRef)
	if underlyingEntry != nil && underlyingEntry.Tag == dwarf.TagSubroutineType {
		return readFuncPtrValue(ptrVal)
	}

	// Read the dereferenced value
	derefValue := readValueAtAddress(d, ptrVal, underlyingRef, depth+1)
	return "&" + derefValue
}

// readFuncValue reads a function value (which in Go is a pointer to a funcval struct)
func readFuncValue(addr uintptr) string {
	// In Go, a func value is a pointer to a runtime.funcval struct
	// The funcval struct's first field is the function pointer (fn uintptr)
	funcvalPtr := *(*uintptr)(unsafe.Pointer(addr))
	if funcvalPtr == 0 {
		return "nil"
	}

	// Try to use the funcval pointer directly first (for static function references)
	fn := runtime.FuncForPC(funcvalPtr)
	if fn != nil {
		// This is a direct pointer to code - format it
		return formatFuncLocation(funcvalPtr)
	}

	// Otherwise, dereference to get the function pointer from the funcval struct
	funcPtr := *(*uintptr)(unsafe.Pointer(funcvalPtr))
	if funcPtr == 0 {
		return fmt.Sprintf("func(0x%x)", funcvalPtr)
	}
	return formatFuncLocation(funcPtr)
}

// readFuncPtrValue reads a pointer to a function (the pointer holds the code address directly)
func readFuncPtrValue(funcPtr uintptr) string {
	if funcPtr == 0 {
		return "nil"
	}
	return formatFuncLocation(funcPtr)
}

// formatFuncLocation formats a function pointer with its file and line location
func formatFuncLocation(funcPtr uintptr) string {
	fn := runtime.FuncForPC(funcPtr)
	if fn == nil {
		return fmt.Sprintf("func(0x%x)", funcPtr)
	}

	name := fn.Name()
	file, line := fn.FileLine(fn.Entry())

	return fmt.Sprintf("func %s (%s:%d)", name, file, line)
}

// readStructValue reads a struct's fields
func readStructValue(d *dwarf.Data, addr uintptr, typeRef dwarf.Offset, depth int) string {
	members := getStructMembers(d, typeRef)
	if len(members) == 0 {
		return "{}"
	}

	var parts []string
	for _, m := range members {
		fieldAddr := addr + uintptr(m.offset)
		fieldValue := readValueAtAddress(d, fieldAddr, m.typeRef, depth+1)
		parts = append(parts, fmt.Sprintf("%s: %s", m.name, fieldValue))
	}

	return "{" + joinStrings(parts, ", ") + "}"
}

// isSliceType checks if the struct members represent a Go slice
func isSliceType(members []memberInfo) bool {
	if len(members) != 3 {
		return false
	}
	// Go slice has: array (pointer), len (int), cap (int)
	hasArray := false
	hasLen := false
	hasCap := false
	for _, m := range members {
		switch m.name {
		case "array":
			hasArray = true
		case "len":
			hasLen = true
		case "cap":
			hasCap = true
		}
	}
	return hasArray && hasLen && hasCap
}

// isStringType checks if the struct members represent a Go string
func isStringType(members []memberInfo) bool {
	if len(members) != 2 {
		return false
	}
	hasStr := false
	hasLen := false
	for _, m := range members {
		switch m.name {
		case "str":
			hasStr = true
		case "len":
			hasLen = true
		}
	}
	return hasStr && hasLen
}

// maxStringLen is the maximum number of bytes to read from a string
const maxStringLen = 256

// readStringValue reads a Go string from memory
func readStringValue(addr uintptr) string {
	type stringHeader struct {
		Data uintptr
		Len  int
	}
	hdr := *(*stringHeader)(unsafe.Pointer(addr))

	if hdr.Len == 0 {
		return `""`
	}

	// Check if data pointer looks valid (not too small to be a real pointer)
	if hdr.Data < 0x1000 {
		return fmt.Sprintf("<invalid string Data=0x%x Len=%d>", hdr.Data, hdr.Len)
	}

	// Cap the length at maxStringLen
	readLen := hdr.Len
	truncated := false
	if readLen > maxStringLen {
		readLen = maxStringLen
		truncated = true
	}
	if readLen < 0 {
		return fmt.Sprintf("<invalid string Data=0x%x Len=%d>", hdr.Data, hdr.Len)
	}

	// Try to read the bytes
	bytes := make([]byte, readLen)
	for i := 0; i < readLen; i++ {
		bytes[i] = *(*byte)(unsafe.Pointer(hdr.Data + uintptr(i)))
	}

	// Format as string with non-printable chars hex-encoded
	result := formatStringBytes(bytes)
	if truncated {
		result += "..."
	}

	return `"` + result + `"`
}

// formatStringBytes formats bytes as a string, hex-encoding non-printable characters
func formatStringBytes(data []byte) string {
	var result []byte
	for _, b := range data {
		if b >= 32 && b < 127 {
			// Printable ASCII
			if b == '"' || b == '\\' {
				result = append(result, '\\', b)
			} else {
				result = append(result, b)
			}
		} else if b == '\n' {
			result = append(result, '\\', 'n')
		} else if b == '\r' {
			result = append(result, '\\', 'r')
		} else if b == '\t' {
			result = append(result, '\\', 't')
		} else {
			// Hex encode non-printable
			result = append(result, fmt.Sprintf("\\x%02x", b)...)
		}
	}
	return string(result)
}

// readSliceValue reads a slice header and its elements
func readSliceValue(d *dwarf.Data, addr uintptr, members []memberInfo, depth int) string {
	// Read slice header fields
	var dataPtr uintptr
	var sliceLen, sliceCap int64

	for _, m := range members {
		fieldAddr := addr + uintptr(m.offset)
		switch m.name {
		case "array":
			dataPtr = *(*uintptr)(unsafe.Pointer(fieldAddr))
		case "len":
			sliceLen = *(*int64)(unsafe.Pointer(fieldAddr))
		case "cap":
			sliceCap = *(*int64)(unsafe.Pointer(fieldAddr))
		}
	}

	if dataPtr == 0 || sliceLen == 0 {
		return fmt.Sprintf("[](len=%d, cap=%d)", sliceLen, sliceCap)
	}

	// Get element type from the array pointer
	var elemTypeRef dwarf.Offset
	var elemSize int64
	for _, m := range members {
		if m.name == "array" {
			ptrEntry := getTypeEntry(d, m.typeRef)
			if ptrEntry != nil && ptrEntry.Tag == dwarf.TagPointerType {
				if ref, ok := ptrEntry.Val(dwarf.AttrType).(dwarf.Offset); ok {
					elemTypeRef = ref
					elemSize = getTypeSize(d, elemTypeRef)
				}
			}
			break
		}
	}

	if elemSize == 0 {
		elemSize = 8 // Default to pointer size
	}

	// Read elements
	numToShow := sliceLen
	if numToShow > maxSliceElements {
		numToShow = maxSliceElements
	}

	var elems []string
	for i := int64(0); i < numToShow; i++ {
		elemAddr := dataPtr + uintptr(i*elemSize)
		elemValue := readValueAtAddress(d, elemAddr, elemTypeRef, depth+1)
		elems = append(elems, elemValue)
	}

	result := "[" + joinStrings(elems, ", ")
	if sliceLen > maxSliceElements {
		result += ", ..."
	}
	result += "]"

	return fmt.Sprintf("(len=%d, cap=%d)%s", sliceLen, sliceCap, result)
}

// readArrayValue reads an array's elements
func readArrayValue(d *dwarf.Data, addr uintptr, entry *dwarf.Entry, depth int) string {
	// Get element type
	elemTypeRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset)
	if !ok {
		return "[...]"
	}

	elemSize := getTypeSize(d, elemTypeRef)
	if elemSize == 0 {
		elemSize = 8
	}

	// Get array length from DWARF (from subrange child)
	reader := dwarfData.Reader()
	reader.Seek(entry.Offset)
	reader.Next() // skip the array entry itself

	var arrayLen int64 = 0
	if entry.Children {
		child, err := reader.Next()
		if err == nil && child != nil && child.Tag == dwarf.TagSubrangeType {
			if count, ok := child.Val(dwarf.AttrCount).(int64); ok {
				arrayLen = count
			} else if upper, ok := child.Val(dwarf.AttrUpperBound).(int64); ok {
				arrayLen = upper + 1
			}
		}
	}

	if arrayLen == 0 {
		return "[...]"
	}

	numToShow := arrayLen
	if numToShow > maxSliceElements {
		numToShow = maxSliceElements
	}

	var elems []string
	for i := int64(0); i < numToShow; i++ {
		elemAddr := addr + uintptr(i*elemSize)
		elemValue := readValueAtAddress(d, elemAddr, elemTypeRef, depth+1)
		elems = append(elems, elemValue)
	}

	result := "[" + joinStrings(elems, ", ")
	if arrayLen > maxSliceElements {
		result += ", ..."
	}
	result += "]"

	return result
}

// readPrimitiveValue reads primitive types by name
func readPrimitiveValue(d *dwarf.Data, addr uintptr, entry *dwarf.Entry, typeName string) string {
	// For typedef, follow to the underlying type
	if entry.Tag == dwarf.TagTypedef {
		if underlyingRef, ok := entry.Val(dwarf.AttrType).(dwarf.Offset); ok {
			underlyingEntry := getTypeEntry(d, underlyingRef)
			if underlyingEntry != nil {
				return readPrimitiveValue(d, addr, underlyingEntry, typeName)
			}
		}
	}

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
		// Unknown type - read raw bytes based on size
		size := getTypeSize(d, entry.Offset)
		if size == 0 {
			size = 8
		}
		if size <= 8 {
			bytes := make([]byte, size)
			for i := int64(0); i < size; i++ {
				bytes[i] = *(*byte)(unsafe.Pointer(addr + uintptr(i)))
			}
			return fmt.Sprintf("0x%x", binary.LittleEndian.Uint64(padToEight(bytes)))
		}
		return fmt.Sprintf("<size=%d>", size)
	}
}

// padToEight pads a byte slice to 8 bytes
func padToEight(b []byte) []byte {
	if len(b) >= 8 {
		return b[:8]
	}
	result := make([]byte, 8)
	copy(result, b)
	return result
}

// joinStrings joins strings with a separator (simple implementation to avoid strings import)
func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result += sep + parts[i]
	}
	return result
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
					value := readValueAtAddress(d, addr, v.typeRef, 0)
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
