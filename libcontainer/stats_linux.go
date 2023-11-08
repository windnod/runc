package libcontainer

import (
	"github.com/windnod/runc/libcontainer/cgroups"
	"github.com/windnod/runc/libcontainer/intelrdt"
	"github.com/windnod/runc/types"
)

type Stats struct {
	Interfaces    []*types.NetworkInterface
	CgroupStats   *cgroups.Stats
	IntelRdtStats *intelrdt.Stats
}
