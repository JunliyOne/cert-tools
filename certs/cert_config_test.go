package certs

import (
	"testing"
)

func Test_PrintConfTemp(t *testing.T) {
	// PrintConfTemp("toml")
	PrintConfTemp("yaml")
}

func TestParseFile(t *testing.T) {

	ParseFile(NewCerts(), "./bin/certs.yaml")
}
