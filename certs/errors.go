package certs

import (
	"fmt"
	"os"
)

const (
	CODE_SUCCESS                = 0xE0000
	CODE_UnKnownExt             = 0xE0001
	CODE_FileNotExist           = 0xE0002
	CODE_YamlUnmarshalError     = 0xE0003
	CODE_YamlMarshalError       = 0xE0004
	CODE_TomlUnmarshalError     = 0xE0005
	CODE_TomlMarshalError       = 0xE0006
	CODE_CAInfoNotConfigured    = 0xE0C01
	CODE_CreateCertificateError = 0xE0C02
	// IO OS
	CODE_IoCreateFileError  = 0xE0101
	CODE_IoReadError        = 0xE0102
	CODE_IoWriteError       = 0xE0103
	CODE_OSCommandExecError = 0xE0127
)

var (
	UnKnownExt = Status{
		code: CODE_UnKnownExt,
		msg:  "UnKnown Ext",
	}
	FileNotExist = Status{
		code: CODE_FileNotExist,
		msg:  "File Not Exist",
	}
	YamlUnmarshalError = Status{
		code: CODE_YamlUnmarshalError,
		msg:  "Yaml Unmarshal Error",
	}
	YamlMarshalError = Status{
		code: CODE_YamlMarshalError,
		msg:  "Yaml Marshal Error",
	}
	TomlUnmarshalError = Status{
		code: CODE_TomlUnmarshalError,
		msg:  "Yaml Unmarshal Error",
	}
	TomlMarshalError = Status{
		code: CODE_TomlMarshalError,
		msg:  "Yaml Marshal Error",
	}

	CAInfoNotConfigured = Status{
		code: CODE_CAInfoNotConfigured,
		msg:  "CA information not configured",
	}

	// cert
	CreateCertificateError = Status{
		code: CODE_CreateCertificateError,
		msg:  "Create Certificate Error",
	}

	// io sys
	IoCreateFileError = Status{
		code: CODE_IoCreateFileError,
		msg:  "Io Create File Error",
	}
	IoReadError = Status{
		code: CODE_IoReadError,
		msg:  "Io Read Error",
	}
	IoWriteError = Status{
		code: CODE_IoWriteError,
		msg:  "Io Write Error",
	}
	OSCommandExecError = Status{
		code: CODE_OSCommandExecError,
		msg:  "OS Command Exec Error",
	}
)

type Status struct {
	code int
	msg  string
}

func (s *Status) print() string {
	return fmt.Sprintf("%X: %s", s.code, s.msg)
}

func CheckError(err error) {
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(127)
	}
}
