//go:build linux
// +build linux

package fs

import (
	"github.com/windnod/runc/libcontainer/cgroups"
	"github.com/windnod/runc/libcontainer/configs"
)

type PerfEventGroup struct{}

func (s *PerfEventGroup) Name() string {
	return "perf_event"
}

func (s *PerfEventGroup) Apply(path string, d *cgroupData) error {
	return join(path, d.pid)
}

func (s *PerfEventGroup) Set(_ string, _ *configs.Resources) error {
	return nil
}

func (s *PerfEventGroup) GetStats(path string, stats *cgroups.Stats) error {
	return nil
}
