package main

import (
	"fmt"
	"os"

	"github.com/draganm/delving/introspect"
)

// Demo functions to test stack introspection
//
//go:noinline
func level3(z float64) {
	local3 := "hello from level3"
	count := 42
	_ = local3
	_ = count

	introspect.PrintStackVariables()
}

//go:noinline
func level2(y int) {
	local2 := y * 2
	name := "level2"
	_ = local2
	_ = name

	level3(3.14159)
}

//go:noinline
func level1(x int) {
	local1 := x + 10
	flag := true
	_ = local1
	_ = flag

	level2(x * 2)
}

type X struct {
	A int
	B string
}

func functionWithX(x *X) {
	fmt.Println(x)
}

func main() {
	hasDwarf, err := introspect.HasDWARFInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error checking DWARF info: %v\n", err)
		os.Exit(1)
	}

	if !hasDwarf {
		fmt.Fprintln(os.Stderr, "Binary does not contain DWARF debug information.")
		fmt.Fprintln(os.Stderr, "Build with: go build -gcflags='all=-N -l' -o delving .")
		os.Exit(1)
	}

	fmt.Println("Starting stack introspection demo...")

	fn := functionWithX

	x := &X{
		A: 1,
		B: "hello",
	}

	value := 100
	level1(value)

	fmt.Println("\nDone!")
	fn(x)
}
