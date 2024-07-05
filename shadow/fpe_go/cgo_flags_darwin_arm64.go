//go:build darwin && arm64

package fpe

// #cgo LDFLAGS: -L${SRCDIR}/lib -lshadow_fpe_export_darwin_arm64 -lstdc++
import "C"
