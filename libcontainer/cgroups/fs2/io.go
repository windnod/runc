package fs2

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/opencontainers/runc/libcontainer/cgroups"
	"github.com/opencontainers/runc/libcontainer/configs"
)

const defaultKubeQoSCgroupRoot = "/sys/fs/cgroup/kubepods.slice"

func isIoSet(r *configs.Resources) bool {
	return r.BlkioWeight != 0 ||
		len(r.BlkioWeightDevice) > 0 ||
		len(r.BlkioThrottleReadBpsDevice) > 0 ||
		len(r.BlkioThrottleWriteBpsDevice) > 0 ||
		len(r.BlkioThrottleReadIOPSDevice) > 0 ||
		len(r.BlkioThrottleWriteIOPSDevice) > 0
}

// bfqDeviceWeightSupported checks for per-device BFQ weight support (added
// in kernel v5.4, commit 795fe54c2a8) by reading from "io.bfq.weight".
func bfqDeviceWeightSupported(bfq *os.File) bool {
	if bfq == nil {
		return false
	}
	_, _ = bfq.Seek(0, 0)
	buf := make([]byte, 32)
	_, _ = bfq.Read(buf)
	// If only a single number (default weight) if read back, we have older kernel.
	_, err := strconv.ParseInt(string(bytes.TrimSpace(buf)), 10, 64)
	return err != nil
}

func setIo(dirPath string, r *configs.Resources) error {
	if !isIoSet(r) {
		return nil
	}

	if err := writeBlkIOConfig(dirPath, r); err != nil {
		return err
	}

	//非QoS Cgroup或weight为100或带有Throttle限制的容器都不能作为Pod级别的weight设置
	if r.BlkioWeight == 100 ||
		!cgroups.IsKubeQoSPath(dirPath) ||
		r.BlkioThrottleWriteBpsDevice != nil ||
		r.BlkioThrottleWriteIOPSDevice != nil ||
		r.BlkioThrottleReadBpsDevice != nil ||
		r.BlkioThrottleReadIOPSDevice != nil {
		return nil
	}

	if err := writeBlkIOConfig(cgroups.KubeQoSTrimSuffixPath(dirPath), &configs.Resources{BlkioWeight: r.BlkioWeight, BlkioWeightDevice: r.BlkioWeightDevice}); err != nil {
		return err
	}

	return nil
}

/*
func updateParentMemory(podPath string) error {
	const file = "memory.max"

	qoSMemorySize, err := os.ReadFile(cgroups.KubeQoSTrimSuffixPath(podPath) + "/" + file)
	if err != nil {
		return err
	} else if !strings.Contains(string(qoSMemorySize), "max") {
		return nil
	}

	nodeMemorySize, err := os.ReadFile(defaultKubeQoSCgroupRoot + "/" + file)
	if err != nil {
		return err
	}

	m, err := cgroups.OpenFile(cgroups.KubeQoSTrimSuffixPath(podPath), file, os.O_RDWR)
	if err == nil {
		defer m.Close()
	} else if !os.IsNotExist(err) {
		return err
	}
	if _, err := m.WriteString(string(nodeMemorySize)); err != nil {
		return err
	}

	return nil
}
*/

func writeBlkIOConfig(dirPath string, r *configs.Resources) error {
	// If BFQ IO scheduler is available, use it.
	var bfq *os.File
	if r.BlkioWeight != 0 || len(r.BlkioWeightDevice) > 0 {
		var err error
		bfq, err = cgroups.OpenFile(dirPath, "io.bfq.weight", os.O_RDWR)
		if err == nil {
			defer bfq.Close()
		} else if !os.IsNotExist(err) {
			return err
		}
	}

	if r.BlkioWeight != 0 {
		if bfq != nil { // Use BFQ.
			if _, err := bfq.WriteString(strconv.FormatUint(uint64(r.BlkioWeight), 10)); err != nil {
				return err
			}
		} else {
			// Fallback to io.weight with a conversion scheme.
			v := cgroups.ConvertBlkIOToIOWeightValue(r.BlkioWeight)
			if err := cgroups.WriteFile(dirPath, "io.weight", strconv.FormatUint(v, 10)); err != nil {
				return err
			}
		}
	}
	if bfqDeviceWeightSupported(bfq) {
		for _, wd := range r.BlkioWeightDevice {
			if _, err := bfq.WriteString(wd.WeightString() + "\n"); err != nil {
				return fmt.Errorf("setting device weight %q: %w", wd.WeightString(), err)
			}
		}
	}
	for _, td := range r.BlkioThrottleReadBpsDevice {
		if err := cgroups.WriteFile(dirPath, "io.max", td.StringName("rbps")); err != nil {
			return err
		}
	}
	for _, td := range r.BlkioThrottleWriteBpsDevice {
		if err := cgroups.WriteFile(dirPath, "io.max", td.StringName("wbps")); err != nil {
			return err
		}
	}
	for _, td := range r.BlkioThrottleReadIOPSDevice {
		if err := cgroups.WriteFile(dirPath, "io.max", td.StringName("riops")); err != nil {
			return err
		}
	}
	for _, td := range r.BlkioThrottleWriteIOPSDevice {
		if err := cgroups.WriteFile(dirPath, "io.max", td.StringName("wiops")); err != nil {
			return err
		}
	}

	return nil
}

/*
func readBfqWeightFile(dirPath string) (*configs.Resources, error) {
	r := new(configs.Resources)

	f, err := cgroups.OpenFile(dirPath, BfqIOfile, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for i := 0; scanner.Scan(); i++ {
		wd := new(configs.WeightDevice)
		if i == 0 {
			parts := strings.Fields(scanner.Text())
			weight, err := strconv.ParseUint(parts[1], 10, 16)
			if err != nil {
				return nil, &parseError{Path: dirPath, File: BfqIOfile, Err: err}
			}
			r.BlkioWeight = uint16(weight)
			continue
		}

		parts := strings.Fields(scanner.Text())
		ioDevice := strings.Split(parts[0], ":")

		wd.Major, err = strconv.ParseInt(ioDevice[0], 10, 64)
		if err != nil {
			return nil, &parseError{Path: dirPath, File: BfqIOfile, Err: err}
		}
		wd.Minor, err = strconv.ParseInt(ioDevice[1], 10, 64)
		if err != nil {
			return nil, &parseError{Path: dirPath, File: BfqIOfile, Err: err}
		}
		weight, err := strconv.ParseUint(parts[1], 10, 16)
		if err != nil {
			return nil, &parseError{Path: dirPath, File: BfqIOfile, Err: err}
		}
		wd.Weight = uint16(weight)

		r.BlkioWeightDevice = append(r.BlkioWeightDevice, wd)

	}

	return r, nil
}
*/

func readCgroup2MapFile(dirPath string, name string) (map[string][]string, error) {
	ret := map[string][]string{}
	f, err := cgroups.OpenFile(dirPath, name, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		ret[parts[0]] = parts[1:]
	}
	if err := scanner.Err(); err != nil {
		return nil, &parseError{Path: dirPath, File: name, Err: err}
	}
	return ret, nil
}

func statIo(dirPath string, stats *cgroups.Stats) error {
	const file = "io.stat"
	values, err := readCgroup2MapFile(dirPath, file)
	if err != nil {
		return err
	}
	// more details on the io.stat file format: https://www.kernel.org/doc/Documentation/cgroup-v2.txt
	var parsedStats cgroups.BlkioStats
	for k, v := range values {
		d := strings.Split(k, ":")
		if len(d) != 2 {
			continue
		}
		major, err := strconv.ParseUint(d[0], 10, 64)
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}
		minor, err := strconv.ParseUint(d[1], 10, 64)
		if err != nil {
			return &parseError{Path: dirPath, File: file, Err: err}
		}

		for _, item := range v {
			d := strings.Split(item, "=")
			if len(d) != 2 {
				continue
			}
			op := d[0]

			// Map to the cgroupv1 naming and layout (in separate tables).
			var targetTable *[]cgroups.BlkioStatEntry
			switch op {
			// Equivalent to cgroupv1's blkio.io_service_bytes.
			case "rbytes":
				op = "Read"
				targetTable = &parsedStats.IoServiceBytesRecursive
			case "wbytes":
				op = "Write"
				targetTable = &parsedStats.IoServiceBytesRecursive
			// Equivalent to cgroupv1's blkio.io_serviced.
			case "rios":
				op = "Read"
				targetTable = &parsedStats.IoServicedRecursive
			case "wios":
				op = "Write"
				targetTable = &parsedStats.IoServicedRecursive
			default:
				// Skip over entries we cannot map to cgroupv1 stats for now.
				// In the future we should expand the stats struct to include
				// them.
				logrus.Debugf("cgroupv2 io stats: skipping over unmappable %s entry", item)
				continue
			}

			value, err := strconv.ParseUint(d[1], 10, 64)
			if err != nil {
				return &parseError{Path: dirPath, File: file, Err: err}
			}

			entry := cgroups.BlkioStatEntry{
				Op:    op,
				Major: major,
				Minor: minor,
				Value: value,
			}
			*targetTable = append(*targetTable, entry)
		}
	}
	stats.BlkioStats = parsedStats
	return nil
}
