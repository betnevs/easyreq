package easyreq

import (
	"os"
)

func ExampleLogger_Debugf() {
	l := createLogger(false, os.Stdout)
	l.Debugf("message")
	// Output: [easyreq] DEBUG message
}

func ExampleLogger_Errorf() {
	l := createLogger(false, os.Stdout)
	l.Errorf("message")
	// Output: [easyreq] ERROR message
}

func ExampleLogger_Warnf() {
	l := createLogger(false, os.Stdout)
	l.Warnf("message")
	// Output: [easyreq] WARN message
}
