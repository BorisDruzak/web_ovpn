package helper

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const (
	sourceISOPath = "/usr/share/alt-install/source_iso.json"
	buildIDPath   = "/usr/share/alt-install/build-id"
	agentVersion  = "1.0.0"
)

type readOnlySystemProbe interface {
	ReadFile(path string) ([]byte, error)
	ReadDirectory(path string) ([]string, error)
	Run(ctx context.Context, name string, arguments ...string) ([]byte, error)
}

type operatingSystemProbe struct{}

func (operatingSystemProbe) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (operatingSystemProbe) ReadDirectory(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry.Name())
	}
	return result, nil
}

func (operatingSystemProbe) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	switch name {
	case "/usr/sbin/blkid", "ip":
	default:
		return nil, contractError("inventory_probe_invalid", "inventory command is not allowlisted")
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = nil
	return command.Output()
}

type blockDevice struct {
	Name       string        `json:"name"`
	Type       string        `json:"type"`
	Path       string        `json:"path"`
	Removable  bool          `json:"rm"`
	Size       flexibleInt64 `json:"size"`
	Model      string        `json:"model"`
	Serial     *string       `json:"serial"`
	WWN        *string       `json:"wwn"`
	FSType     *string       `json:"fstype"`
	Mountpoint *string       `json:"mountpoint"`
	Children   []blockDevice `json:"children"`
}

type flexibleInt64 int64

func (value *flexibleInt64) UnmarshalJSON(raw []byte) error {
	text := string(raw)
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		text = text[1 : len(text)-1]
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil || parsed < 0 {
		return errors.New("invalid non-negative integer")
	}
	*value = flexibleInt64(parsed)
	return nil
}

type ipInterface struct {
	Name      string `json:"ifname"`
	MAC       string `json:"address"`
	Addresses []struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	} `json:"addr_info"`
}

type ipRoute struct {
	Device string `json:"dev"`
}

func collectSystemInventory(ctx context.Context, probe readOnlySystemProbe) ([]byte, error) {
	sourceRaw, err := probe.ReadFile(sourceISOPath)
	if err != nil {
		return nil, contractError("inventory_source_iso_unavailable", "source ISO identity is unavailable")
	}
	source, err := parseSourceISO(sourceRaw)
	if err != nil {
		return nil, err
	}
	buildID, err := readBoundedText(probe, buildIDPath)
	if err != nil {
		return nil, contractError("inventory_build_id_unavailable", "managed build ID is unavailable")
	}
	bootID, err := readBoundedText(probe, "/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, contractError("inventory_boot_id_unavailable", "boot ID is unavailable")
	}
	controllerHost, err := controllerHostFromCmdline(probe)
	if err != nil {
		return nil, err
	}
	machine, err := collectMachine(probe)
	if err != nil {
		return nil, err
	}

	blockDevices, err := collectBlockDevices(ctx, probe)
	if err != nil {
		return nil, contractError("inventory_disk_probe_failed", "block inventory probe failed")
	}
	disks, bootMedia, err := inventoryDisks(blockDevices)
	if err != nil {
		return nil, err
	}

	addressRaw, err := probe.Run(ctx, "ip", "-j", "address", "show")
	if err != nil || len(addressRaw) > maxDocumentBytes {
		return nil, contractError("inventory_network_probe_failed", "network address probe failed")
	}
	var addressDocument []ipInterface
	addressDecoder := json.NewDecoder(bytes.NewReader(addressRaw))
	if err := addressDecoder.Decode(&addressDocument); err != nil {
		return nil, contractError("inventory_network_probe_invalid", "network address probe returned invalid JSON")
	}
	routeRaw, err := probe.Run(ctx, "ip", "-j", "route", "get", controllerHost)
	if err != nil || len(routeRaw) > maxDocumentBytes {
		return nil, contractError("inventory_route_probe_failed", "controller route probe failed")
	}
	var routeDocument []ipRoute
	routeDecoder := json.NewDecoder(bytes.NewReader(routeRaw))
	if err := routeDecoder.Decode(&routeDocument); err != nil || len(routeDocument) != 1 || routeDocument[0].Device == "" {
		return nil, contractError("inventory_route_probe_invalid", "controller route probe is ambiguous")
	}
	interfaces, err := inventoryInterfaces(addressDocument, routeDocument[0].Device)
	if err != nil {
		return nil, err
	}

	inventory := Inventory{
		SchemaVersion: 1,
		Agent: AgentInventory{
			Version: agentVersion, BootID: bootID, BuildID: buildID, ISOID: source.ISOID, ISOSHA256: source.ISOSHA256,
		},
		Machine: machine, Interfaces: interfaces, Disks: disks, BootMedia: bootMedia,
	}
	canonical, err := canonicalJSON(inventoryMap(inventory))
	if err != nil {
		return nil, err
	}
	if _, err := ParseInventory(canonical); err != nil {
		return nil, err
	}
	return canonical, nil
}

func collectBlockDevices(ctx context.Context, probe readOnlySystemProbe) ([]blockDevice, error) {
	names, err := probe.ReadDirectory("/sys/class/block")
	if err != nil || len(names) == 0 {
		return nil, errors.New("block devices are unavailable")
	}
	sort.Strings(names)
	mounts, err := imageMounts(probe)
	if err != nil {
		return nil, err
	}
	topLevel := make([]string, 0, len(names))
	for _, name := range names {
		if !safeBlockName(name) {
			return nil, errors.New("block device name is unsafe")
		}
		if _, err := probe.ReadFile("/sys/class/block/" + name + "/partition"); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		topLevel = append(topLevel, name)
	}
	if err := validateImageMountTopology(probe, names, topLevel, mounts); err != nil {
		return nil, err
	}
	devices := make([]blockDevice, 0, len(topLevel))
	for _, name := range topLevel {
		kind, err := sysfsBlockType(probe, name)
		if err != nil {
			return nil, err
		}
		if kind == "unsupported" {
			continue
		}
		device, err := readBlockDevice(ctx, probe, name, "", mounts)
		if err != nil {
			return nil, err
		}
		for _, child := range names {
			if blockParentName(child, topLevel) != name {
				continue
			}
			partition, err := readBlockDevice(ctx, probe, child, "part", mounts)
			if err != nil {
				return nil, err
			}
			device.Children = append(device.Children, partition)
		}
		devices = append(devices, device)
	}
	return devices, nil
}

func validateImageMountTopology(probe readOnlySystemProbe, names, topLevel []string, mounts map[string]string) error {
	for dev := range mounts {
		mountedName := ""
		for _, name := range names {
			value, err := readBoundedText(probe, "/sys/class/block/"+name+"/dev")
			if err != nil {
				return err
			}
			if value == dev {
				if mountedName != "" {
					return errors.New("boot media is ambiguous")
				}
				mountedName = name
			}
		}
		if mountedName == "" {
			return errors.New("boot media device is unavailable")
		}
		physicalName := mountedName
		if parent := blockParentName(mountedName, topLevel); parent != "" {
			physicalName = parent
		}
		kind, err := sysfsBlockType(probe, physicalName)
		if err != nil {
			return err
		}
		if kind != "disk" && kind != "rom" {
			return errors.New("boot media topology is unsupported")
		}
	}
	return nil
}

func imageMounts(probe readOnlySystemProbe) (map[string]string, error) {
	raw, err := probe.ReadFile("/proc/self/mountinfo")
	if err != nil || len(raw) > maxDocumentBytes || !utf8Valid(raw) {
		return nil, errors.New("mount information is unavailable")
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[4] == "/image" {
			result[fields[2]] = "/image"
		}
	}
	return result, nil
}

func readBlockDevice(ctx context.Context, probe readOnlySystemProbe, name, forcedType string, mounts map[string]string) (blockDevice, error) {
	base := "/sys/class/block/" + name
	dev, err := readBoundedText(probe, base+"/dev")
	if err != nil {
		return blockDevice{}, err
	}
	sizeSectors, err := readPositiveInt(probe, base+"/size")
	if err != nil {
		return blockDevice{}, err
	}
	const sectorSize = int64(512)
	if sizeSectors > (1<<63-1)/sectorSize {
		return blockDevice{}, errors.New("block device size is invalid")
	}
	removableText, err := readBoundedText(probe, base+"/removable")
	if forcedType == "part" && errors.Is(err, os.ErrNotExist) {
		removableText = "0"
		err = nil
	}
	if err != nil || (removableText != "0" && removableText != "1") {
		return blockDevice{}, errors.New("removable state is invalid")
	}
	deviceType := forcedType
	if deviceType == "" {
		deviceType, err = sysfsBlockType(probe, name)
		if err != nil {
			return blockDevice{}, err
		}
	}
	model, err := optionalBoundedText(probe, base+"/device/model")
	if err != nil {
		return blockDevice{}, err
	}
	serial, err := optionalBoundedText(probe, base+"/device/serial")
	if err != nil {
		return blockDevice{}, err
	}
	wwn, err := optionalBoundedText(probe, base+"/device/wwid")
	if err != nil {
		return blockDevice{}, err
	}
	filesystem, err := blockFilesystem(ctx, probe, name)
	if err != nil {
		return blockDevice{}, err
	}
	return blockDevice{
		Name: name, Type: deviceType, Path: "/dev/" + name, Removable: removableText == "1",
		Size: flexibleInt64(sizeSectors * sectorSize), Model: dereferenceText(model), Serial: serial, WWN: wwn,
		FSType: filesystem, Mountpoint: optionalMountpoint(mounts, dev),
	}, nil
}

func blockFilesystem(ctx context.Context, probe readOnlySystemProbe, name string) (*string, error) {
	raw, err := probe.Run(ctx, "/usr/sbin/blkid", "-o", "export", "/dev/"+name)
	if err != nil && len(raw) == 0 {
		return nil, nil
	}
	if len(raw) > maxDocumentBytes || !utf8Valid(raw) {
		return nil, errors.New("filesystem probe is invalid")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "TYPE=") {
			continue
		}
		value := strings.TrimPrefix(line, "TYPE=")
		if value == "" || len([]rune(value)) > maxStringRunes {
			return nil, errors.New("filesystem type is invalid")
		}
		return &value, nil
	}
	return nil, nil
}

func sysfsBlockType(probe readOnlySystemProbe, name string) (string, error) {
	raw, err := probe.ReadFile("/sys/class/block/" + name + "/device/type")
	if err == nil {
		value, err := boundedText(raw)
		if err != nil {
			return "", err
		}
		switch value {
		case "0":
			return "disk", nil
		case "5":
			return "rom", nil
		default:
			return "unsupported", nil
		}
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	for _, prefix := range []string{"sd", "vd", "xvd", "hd", "nvme", "mmcblk"} {
		if strings.HasPrefix(name, prefix) {
			return "disk", nil
		}
	}
	return "unsupported", nil
}

func readPositiveInt(probe readOnlySystemProbe, path string) (int64, error) {
	text, err := readBoundedText(probe, path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value <= 0 {
		return 0, errors.New("positive integer is invalid")
	}
	return value, nil
}

func optionalBoundedText(probe readOnlySystemProbe, path string) (*string, error) {
	value, err := readBoundedText(probe, path)
	if err != nil {
		if _, readErr := probe.ReadFile(path); errors.Is(readErr, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return &value, nil
}

func optionalMountpoint(mounts map[string]string, dev string) *string {
	if value, ok := mounts[dev]; ok {
		return &value
	}
	return nil
}

func dereferenceText(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func safeBlockName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if !((character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-') {
			return false
		}
	}
	return true
}

func blockParentName(name string, topLevel []string) string {
	parent := ""
	for _, candidate := range topLevel {
		if !strings.HasPrefix(name, candidate) || len(name) == len(candidate) {
			continue
		}
		suffix := strings.TrimPrefix(name, candidate)
		if suffix[0] == 'p' {
			suffix = suffix[1:]
		}
		if suffix == "" {
			continue
		}
		for _, character := range suffix {
			if character < '0' || character > '9' {
				goto nextCandidate
			}
		}
		if len(candidate) > len(parent) {
			parent = candidate
		}
	nextCandidate:
	}
	return parent
}

func collectMachine(probe readOnlySystemProbe) (MachineInventory, error) {
	values := make(map[string]string, 4)
	for field, path := range map[string]string{
		"dmi_uuid": "/sys/class/dmi/id/product_uuid", "manufacturer": "/sys/class/dmi/id/sys_vendor",
		"product_name": "/sys/class/dmi/id/product_name", "serial_number": "/sys/class/dmi/id/product_serial",
	} {
		value, err := readBoundedText(probe, path)
		if err != nil {
			return MachineInventory{}, contractError("inventory_machine_probe_failed", "DMI inventory is unavailable")
		}
		values[field] = value
	}
	meminfo, err := probe.ReadFile("/proc/meminfo")
	if err != nil || len(meminfo) > maxDocumentBytes {
		return MachineInventory{}, contractError("inventory_machine_probe_failed", "memory inventory is unavailable")
	}
	var memoryKiB int64
	for _, line := range strings.Split(string(meminfo), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			memoryKiB, err = strconv.ParseInt(fields[1], 10, 64)
			break
		}
	}
	if err != nil || memoryKiB <= 0 || memoryKiB > (1<<63-1)/1024 {
		return MachineInventory{}, contractError("inventory_machine_probe_failed", "memory inventory is invalid")
	}
	firmware := "bios"
	if _, err := probe.ReadFile("/sys/firmware/efi/fw_platform_size"); err == nil {
		firmware = "uefi"
	}
	architecture := runtime.GOARCH
	if architecture == "amd64" {
		architecture = "x86_64"
	}
	return MachineInventory{
		DMIUUID: values["dmi_uuid"], Manufacturer: values["manufacturer"], ProductName: values["product_name"],
		SerialNumber: values["serial_number"], Firmware: firmware, MemoryBytes: memoryKiB * 1024, CPUArch: architecture,
	}, nil
}

func controllerHostFromCmdline(probe readOnlySystemProbe) (string, error) {
	raw, err := probe.ReadFile("/proc/cmdline")
	if err != nil || len(raw) > maxDocumentBytes {
		return "", contractError("inventory_controller_missing", "controller endpoint is unavailable")
	}
	for _, item := range strings.Fields(string(raw)) {
		if !strings.HasPrefix(item, "sosnadmin.controller=") {
			continue
		}
		endpoint, err := url.Parse(strings.TrimPrefix(item, "sosnadmin.controller="))
		if err != nil || endpoint.Hostname() == "" {
			break
		}
		return endpoint.Hostname(), nil
	}
	return "", contractError("inventory_controller_missing", "controller endpoint is unavailable")
}

func inventoryDisks(devices []blockDevice) ([]DiskInventory, BootMediaInventory, error) {
	disks := make([]DiskInventory, 0, len(devices))
	var boot *blockDevice
	for index := range devices {
		device := &devices[index]
		if findMountpoint(device, "/image") != nil {
			if boot != nil {
				return nil, BootMediaInventory{}, contractError("inventory_boot_media_ambiguous", "boot media is ambiguous")
			}
			// Record the top-level physical ancestor. A mounted /dev/sdb1 must
			// exclude /dev/sdb from target eligibility.
			boot = device
		}
		if device.Type != "disk" {
			continue
		}
		signatures := make([]string, 0)
		collectFilesystemSignatures(device, &signatures)
		sort.Strings(signatures)
		disks = append(disks, DiskInventory{
			Type: "disk", Path: device.Path, Removable: device.Removable, SizeBytes: int64(device.Size),
			Model: strings.TrimSpace(device.Model), Serial: cleanOptional(device.Serial), WWN: cleanOptional(device.WWN),
			FilesystemSignatures: uniqueStrings(signatures),
		})
	}
	if boot == nil {
		return nil, BootMediaInventory{}, contractError("inventory_boot_media_missing", "boot media is unavailable")
	}
	sort.Slice(disks, func(left, right int) bool { return disks[left].Path < disks[right].Path })
	return disks, BootMediaInventory{
		Path: boot.Path, Model: strings.TrimSpace(boot.Model), Serial: cleanOptional(boot.Serial), WWN: cleanOptional(boot.WWN),
	}, nil
}

func inventoryInterfaces(document []ipInterface, routeDevice string) ([]InterfaceInventory, error) {
	interfaces := make([]InterfaceInventory, 0, len(document))
	routedFound := false
	for _, item := range document {
		if item.Name == "lo" {
			continue
		}
		addresses := make([]string, 0, len(item.Addresses))
		for _, address := range item.Addresses {
			if net.ParseIP(address.Local) == nil || address.PrefixLen < 0 || address.PrefixLen > 128 {
				return nil, contractError("inventory_network_probe_invalid", "network address is invalid")
			}
			addresses = append(addresses, address.Local+"/"+strconv.Itoa(address.PrefixLen))
		}
		sort.Strings(addresses)
		routed := item.Name == routeDevice
		if routed {
			routedFound = true
		}
		interfaces = append(interfaces, InterfaceInventory{
			Name: item.Name, MAC: strings.ToLower(item.MAC), Addresses: addresses, RouteToController: routed,
		})
	}
	if !routedFound {
		return nil, contractError("inventory_route_probe_invalid", "routed interface is absent")
	}
	sort.Slice(interfaces, func(left, right int) bool { return interfaces[left].Name < interfaces[right].Name })
	return interfaces, nil
}

func readBoundedText(probe readOnlySystemProbe, path string) (string, error) {
	raw, err := probe.ReadFile(path)
	if err != nil {
		return "", err
	}
	return boundedText(raw)
}

func boundedText(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw) > maxStringRunes*4+2 || !utf8Valid(raw) {
		return "", errors.New("invalid bounded text")
	}
	text := strings.TrimSpace(string(raw))
	if text == "" || len([]rune(text)) > maxStringRunes {
		return "", errors.New("invalid bounded text")
	}
	return text, nil
}

func utf8Valid(raw []byte) bool {
	return strings.ToValidUTF8(string(raw), "\ufffd") == string(raw)
}

func findMountpoint(device *blockDevice, mountpoint string) *blockDevice {
	if device.Mountpoint != nil && *device.Mountpoint == mountpoint {
		return device
	}
	for index := range device.Children {
		if found := findMountpoint(&device.Children[index], mountpoint); found != nil {
			return found
		}
	}
	return nil
}

func collectFilesystemSignatures(device *blockDevice, result *[]string) {
	if device.FSType != nil {
		value := strings.TrimSpace(*device.FSType)
		if value != "" {
			*result = append(*result, value)
		}
	}
	for index := range device.Children {
		collectFilesystemSignatures(&device.Children[index], result)
	}
}

func cleanOptional(value *string) *string {
	if value == nil {
		return nil
	}
	clean := strings.TrimSpace(*value)
	if clean == "" {
		return nil
	}
	return &clean
}

func uniqueStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
