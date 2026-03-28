package main

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ANSI color codes — only emitted when stdout is a terminal.
var (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

func init() {
	if !isTerminal() {
		colorReset = ""
		colorRed = ""
		colorGreen = ""
		colorYellow = ""
		colorCyan = ""
		colorBold = ""
		colorDim = ""
	}
}

func isTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// Colored output helpers.

func green(s string) string  { return colorGreen + s + colorReset }
func red(s string) string    { return colorRed + s + colorReset }
func yellow(s string) string { return colorYellow + s + colorReset }
func cyan(s string) string   { return colorCyan + s + colorReset }
func bold(s string) string   { return colorBold + s + colorReset }
func dim(s string) string    { return colorDim + s + colorReset }

func checkMark() string { return green("✓") }
func crossMark() string { return red("✗") }
func warnMark() string  { return yellow("⚠") }

func printSuccess(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "  %s %s\n", checkMark(), fmt.Sprintf(format, args...))
}

func printFailure(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "  %s %s\n", crossMark(), fmt.Sprintf(format, args...))
}

func printWarning(w io.Writer, format string, args ...any) {
	fmt.Fprintf(w, "  %s %s\n", warnMark(), fmt.Sprintf(format, args...))
}
