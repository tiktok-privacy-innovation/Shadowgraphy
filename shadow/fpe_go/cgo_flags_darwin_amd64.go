//go:build darwin && amd64

package fpe

// #cgo LDFLAGS: -L${SRCDIR}/lib -lshadow_fpe_export_darwin_amd64 -Wl,-rpath,${SRCDIR}/lib
import "C"
