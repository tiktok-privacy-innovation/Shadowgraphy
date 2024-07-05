//go:build linux

package fpe

// #cgo LDFLAGS: -L${SRCDIR}/lib -lshadow_fpe_export_linux_amd64 -lm -lstdc++
import "C"
