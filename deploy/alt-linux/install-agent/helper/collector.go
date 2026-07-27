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
	Run(ctx context.Context, name string, arguments ...string) ([]byte, error)
}

type operatingSystemProbe struct{}

func (operatingSystemProbe) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (operatingSystemProbe) Run(ctx context.Context, name string, arguments ...string) ([]byte, error) {
	switch name {
	case "lsblk", "ip":
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

	blockRaw, err := probe.Run(ctx, "lsblk", "--json", "--bytes", "--output", "NAME,TYPE,PATH,RM,SIZE,MODEL,SERIAL,WWN,FSTYPE,MOUNTPOINT")
	if err != nil || len(blockRaw) > maxDocumentBytes {
		return nil, contractError("inventory_disk_probe_failed", "block inventory probe failed")
	}
	var blockDocument struct {
		Devices []blockDevice `json:"blockdevices"`
	}
	blockDecoder := json.NewDecoder(bytes.NewReader(blockRaw))
	blockDecoder.DisallowUnknownFields()
	if err := blockDecoder.Decode(&blockDocument); err != nil {
		return nil, contractError("inventory_disk_probe_invalid", "block inventory probe returned invalid JSON")
	}
	disks, bootMedia, err := inventoryDisks(blockDocument.Devices)
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
	if err != nil || len(raw) == 0 || len(raw) > maxStringRunes*4+2 || !utf8Valid(raw) {
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
