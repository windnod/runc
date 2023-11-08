//go:build linux
// +build linux

package libcontainer

import (
	"testing"

	"github.com/windnod/runc/libcontainer/configs"
)

func TestCheckMountDestOnProc(t *testing.T) {
	dest := "/rootfs/proc/sys"
	err := checkProcMount("/rootfs", dest, "")
	if err == nil {
		t.Fatal("destination inside proc should return an error")
	}
}

func TestCheckMountDestOnProcChroot(t *testing.T) {
	dest := "/rootfs/proc/"
	err := checkProcMount("/rootfs", dest, "/proc")
	if err != nil {
		t.Fatal("destination inside proc when using chroot should not return an error")
	}
}

func TestCheckMountDestInSys(t *testing.T) {
	dest := "/rootfs//sys/fs/cgroup"
	err := checkProcMount("/rootfs", dest, "")
	if err != nil {
		t.Fatal("destination inside /sys should not return an error")
	}
}

func TestCheckMountDestFalsePositive(t *testing.T) {
	dest := "/rootfs/sysfiles/fs/cgroup"
	err := checkProcMount("/rootfs", dest, "")
	if err != nil {
		t.Fatal(err)
	}
}

func TestNeedsSetupDev(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/dev",
				Destination: "/dev",
			},
		},
	}
	if needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be false, got true")
	}
}

func TestNeedsSetupDevStrangeSource(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/devx",
				Destination: "/dev",
			},
		},
	}
	if needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be false, got true")
	}
}

func TestNeedsSetupDevStrangeDest(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/dev",
				Destination: "/devx",
			},
		},
	}
	if !needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be true, got false")
	}
}

func TestNeedsSetupDevStrangeSourceDest(t *testing.T) {
	config := &configs.Config{
		Mounts: []*configs.Mount{
			{
				Device:      "bind",
				Source:      "/devx",
				Destination: "/devx",
			},
		},
	}
	if !needsSetupDev(config) {
		t.Fatal("expected needsSetupDev to be true, got false")
	}
}
