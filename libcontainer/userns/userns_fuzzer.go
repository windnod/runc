//go:build gofuzz
// +build gofuzz

package userns

import (
	"strings"

	"github.com/windnod/runc/libcontainer/user"
)

func FuzzUIDMap(data []byte) int {
	uidmap, _ := user.ParseIDMap(strings.NewReader(string(data)))
	_ = uidMapInUserNS(uidmap)
	return 1
}
