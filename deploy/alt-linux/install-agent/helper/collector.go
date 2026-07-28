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
	"syscall"
)

const (
	sourceISOPath      = "/usr/share/alt-install/source_iso.json"
	buildIDPath        = "/usr/share/alt-install/build-id"
	managedISOSizePath = "/usr/share/alt-install/managed_iso_size_bytes"
	agentVersion       = "1.0.0"
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
	managedISOSize, err := readPositiveInt(probe, managedISOSizePath)
	if err != nil {
		return nil, contractError("inventory_boot_media_size_unavailable", "managed ISO size is unavailable")
	}
	disks, bootMedia, err := inventoryDisks(blockDevices, managedISOSize)
	if err != nil {
		return nil, err
	}

	interfaces, err := collectNetworkInterfaces(ctx, probe, controllerHost)
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

func collectNetworkInterfaces(ctx context.Context, probe readOnlySystemProbe, controllerHost string) ([]InterfaceInventory, error) {
	addressRaw, addressErr := probe.Run(ctx, "ip", "-j", "address", "show")
	if addressErr == nil && len(addressRaw) <= maxDocumentBytes {
		var addressDocument []ipInterface
		if json.NewDecoder(bytes.NewReader(addressRaw)).Decode(&addressDocument) == nil {
			routeRaw, routeErr := probe.Run(ctx, "ip", "-j", "route", "get", controllerHost)
			if routeErr == nil && len(routeRaw) <= maxDocumentBytes {
				var routeDocument []ipRoute
				if json.NewDecoder(bytes.NewReader(routeRaw)).Decode(&routeDocument) == nil {
					if len(routeDocument) != 1 || routeDocument[0].Device == "" {
						return nil, contractError("inventory_route_probe_invalid", "controller route probe is ambiguous")
					}
					return inventoryInterfaces(addressDocument, routeDocument[0].Device)
				}
			}
		}
	}
	return collectBusyBoxNetworkInterfaces(ctx, probe, controllerHost)
}

func collectBusyBoxNetworkInterfaces(ctx context.Context, probe readOnlySystemProbe, controllerHost string) ([]InterfaceInventory, error) {
	addressRaw, err := probe.Run(ctx, "ip", "-o", "address", "show")
	if err != nil || len(addressRaw) > maxDocumentBytes || !utf8Valid(addressRaw) {
		return nil, contractError("inventory_network_probe_failed", "network address probe failed")
	}
	linkRaw, err := probe.Run(ctx, "ip", "-o", "link", "show")
	if err != nil || len(linkRaw) > maxDocumentBytes || !utf8Valid(linkRaw) {
		return nil, contractError("inventory_network_probe_failed", "network link probe failed")
	}
	routeRaw, err := probe.Run(ctx, "ip", "route", "list")
	if err != nil || len(routeRaw) > maxDocumentBytes || !utf8Valid(routeRaw) {
		return nil, contractError("inventory_route_probe_failed", "controller route probe failed")
	}
	addresses, err := parseBusyBoxAddresses(string(addressRaw))
	if err != nil {
		return nil, contractError("inventory_network_probe_invalid", "network address probe is invalid")
	}
	macs, err := parseBusyBoxLinks(string(linkRaw))
	if err != nil {
		return nil, contractError("inventory_network_probe_invalid", "network link probe is invalid")
	}
	routeDevice, err := parseBusyBoxRouteToHost(string(routeRaw), controllerHost)
	if err != nil {
		return nil, contractError("inventory_route_probe_invalid", "controller route probe is ambiguous")
	}
	document := make([]ipInterface, 0, len(macs))
	for name, mac := range macs {
		document = append(document, ipInterface{Name: name, MAC: mac, Addresses: addresses[name]})
	}
	return inventoryInterfaces(document, routeDevice)
}

func parseBusyBoxAddresses(raw string) (map[string][]struct {
	Local     string `json:"local"`
	PrefixLen int    `json:"prefixlen"`
}, error) {
	result := make(map[string][]struct {
		Local     string `json:"local"`
		PrefixLen int    `json:"prefixlen"`
	})
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 4 || !strings.HasSuffix(fields[0], ":") {
			return nil, errors.New("address line is invalid")
		}
		if fields[2] != "inet" && fields[2] != "inet6" {
			continue
		}
		ip, prefix, ok := strings.Cut(fields[3], "/")
		prefixLen, err := strconv.Atoi(prefix)
		if !ok || err != nil || net.ParseIP(ip) == nil || prefixLen < 0 || prefixLen > 128 {
			return nil, errors.New("address value is invalid")
		}
		name := strings.TrimSuffix(fields[1], ":")
		if name == "" {
			return nil, errors.New("address interface is invalid")
		}
		result[name] = append(result[name], struct {
			Local     string `json:"local"`
			PrefixLen int    `json:"prefixlen"`
		}{Local: ip, PrefixLen: prefixLen})
	}
	return result, nil
}

func parseBusyBoxLinks(raw string) (map[string]string, error) {
	result := make(map[string]string)
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) < 3 || !strings.HasSuffix(fields[0], ":") || !strings.HasSuffix(fields[1], ":") {
			return nil, errors.New("link line is invalid")
		}
		for index := range fields {
			if fields[index] != "link/ether" || index+1 >= len(fields) {
				continue
			}
			if _, err := net.ParseMAC(fields[index+1]); err != nil {
				return nil, errors.New("link MAC is invalid")
			}
			result[strings.TrimSuffix(fields[1], ":")] = strings.ToLower(fields[index+1])
			break
		}
	}
	return result, nil
}

func parseBusyBoxRouteToHost(raw, host string) (string, error) {
	destination := net.ParseIP(host)
	if destination == nil {
		return "", errors.New("controller host is not an IP address")
	}
	bestPrefix := -1
	devices := make(map[string]struct{})
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		prefix := 0
		if fields[0] != "default" {
			ip, network, err := net.ParseCIDR(fields[0])
			if err != nil {
				if ip = net.ParseIP(fields[0]); ip == nil {
					continue
				}
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				network = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
			}
			ones, _ := network.Mask.Size()
			if !network.Contains(destination) {
				continue
			}
			prefix = ones
		}
		if prefix < bestPrefix {
			continue
		}
		if prefix > bestPrefix {
			bestPrefix = prefix
			clear(devices)
		}
		for index := range fields {
			if fields[index] == "dev" && index+1 < len(fields) {
				devices[fields[index+1]] = struct{}{}
				break
			}
		}
	}
	if bestPrefix < 0 || len(devices) != 1 {
		return "", errors.New("controller route is ambiguous")
	}
	for device := range devices {
		return device, nil
	}
	return "", errors.New("controller route is unavailable")
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
	modelValue := dereferenceText(model)
	if modelValue == "" {
		modelValue = "unknown"
	}
	serial, err := optionalDeviceIdentity(probe, base+"/device/serial", base+"/serial")
	if err != nil {
		return blockDevice{}, err
	}
	wwn, err := optionalDeviceIdentity(probe, base+"/device/wwid", base+"/wwid")
	if err != nil {
		return blockDevice{}, err
	}
	filesystem, err := blockFilesystem(ctx, probe, name)
	if err != nil {
		return blockDevice{}, err
	}
	return blockDevice{
		Name: name, Type: deviceType, Path: "/dev/" + name, Removable: removableText == "1",
		Size: flexibleInt64(sizeSectors * sectorSize), Model: modelValue, Serial: serial, WWN: wwn,
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
	raw, err := probe.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(raw) < 2 || len(raw) > maxStringRunes*4+2 || raw[len(raw)-1] != '\n' || raw[0] == '0' {
		return 0, errors.New("positive integer is invalid")
	}
	for _, character := range raw[:len(raw)-1] {
		if character < '0' || character > '9' {
			return 0, errors.New("positive integer is invalid")
		}
	}
	value, err := strconv.ParseInt(string(raw[:len(raw)-1]), 10, 64)
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

func optionalDeviceIdentityText(probe readOnlySystemProbe, path string) (*string, error) {
	value, err := readBoundedText(probe, path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENXIO) {
			return nil, nil
		}
		return nil, err
	}
	return &value, nil
}

func optionalDeviceIdentity(probe readOnlySystemProbe, primary, fallback string) (*string, error) {
	value, err := optionalDeviceIdentityText(probe, primary)
	if err != nil || value != nil {
		return value, err
	}
	return optionalDeviceIdentityText(probe, fallback)
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

func inventoryDisks(devices []blockDevice, managedISOSizeBytes int64) ([]DiskInventory, BootMediaInventory, error) {
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
		for index := range devices {
			device := &devices[index]
			if device.Type != "rom" || !device.Removable || int64(device.Size) != managedISOSizeBytes {
				continue
			}
			if boot != nil {
				return nil, BootMediaInventory{}, contractError("inventory_boot_media_ambiguous", "boot media is ambiguous")
			}
			boot = device
		}
		if boot == nil {
			return nil, BootMediaInventory{}, contractError("inventory_boot_media_missing", "boot media is unavailable")
		}
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
