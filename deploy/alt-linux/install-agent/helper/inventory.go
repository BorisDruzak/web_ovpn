package helper

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

var (
	sha256Pattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	macPattern       = regexp.MustCompile(`^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$`)
	diskPathPattern  = regexp.MustCompile(`^/dev/(?:sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+|xvd[a-z]+)$`)
	mediaPathPattern = regexp.MustCompile(`^/dev/[A-Za-z0-9._-]+$`)
)

type AgentInventory struct {
	Version   string
	BootID    string
	BuildID   string
	ISOID     string
	ISOSHA256 string
}

type MachineInventory struct {
	DMIUUID      string
	Manufacturer string
	ProductName  string
	SerialNumber string
	Firmware     string
	MemoryBytes  int64
	CPUArch      string
}

type InterfaceInventory struct {
	Name              string
	MAC               string
	Addresses         []string
	RouteToController bool
}

type DiskInventory struct {
	Type                 string
	Path                 string
	Removable            bool
	SizeBytes            int64
	Model                string
	Serial               *string
	WWN                  *string
	FilesystemSignatures []string
}

type BootMediaInventory struct {
	Path   string
	Model  string
	Serial *string
	WWN    *string
}

type Inventory struct {
	SchemaVersion int64
	Agent         AgentInventory
	Machine       MachineInventory
	Interfaces    []InterfaceInventory
	Disks         []DiskInventory
	BootMedia     BootMediaInventory
}

// ParseInventory strictly validates the PR3 InstallInventoryV1 contract.
func ParseInventory(raw []byte) (Inventory, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return Inventory{}, err
	}
	root, err := objectValue(value, "inventory")
	if err != nil {
		return Inventory{}, err
	}
	if err := requireFields(root, []string{"schema_version", "agent", "machine", "interfaces", "disks", "boot_media"}, "inventory"); err != nil {
		return Inventory{}, err
	}
	version, err := positiveIntegerValue(root["schema_version"], "inventory")
	if err != nil {
		return Inventory{}, err
	}
	if version != 1 {
		return Inventory{}, contractError("inventory_schema_unsupported", "inventory schema_version must be 1")
	}
	agent, err := parseAgentInventory(root["agent"])
	if err != nil {
		return Inventory{}, err
	}
	machine, err := parseMachineInventory(root["machine"])
	if err != nil {
		return Inventory{}, err
	}
	interfacesRaw, err := arrayValue(root["interfaces"], "inventory")
	if err != nil {
		return Inventory{}, err
	}
	interfaces := make([]InterfaceInventory, 0, len(interfacesRaw))
	for _, item := range interfacesRaw {
		parsed, err := parseInterfaceInventory(item)
		if err != nil {
			return Inventory{}, err
		}
		interfaces = append(interfaces, parsed)
	}
	disksRaw, err := arrayValue(root["disks"], "inventory")
	if err != nil {
		return Inventory{}, err
	}
	disks := make([]DiskInventory, 0, len(disksRaw))
	for _, item := range disksRaw {
		parsed, err := parseDiskInventory(item)
		if err != nil {
			return Inventory{}, err
		}
		disks = append(disks, parsed)
	}
	bootMedia, err := parseBootMediaInventory(root["boot_media"])
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{
		SchemaVersion: version,
		Agent:         agent, Machine: machine, Interfaces: interfaces, Disks: disks, BootMedia: bootMedia,
	}, nil
}

// CanonicalInventoryBytes returns Python-compatible ensure_ascii/sorted-key
// bytes for a strictly validated inventory document.
func CanonicalInventoryBytes(raw []byte) ([]byte, error) {
	inventory, err := ParseInventory(raw)
	if err != nil {
		return nil, err
	}
	return canonicalJSON(inventoryMap(inventory))
}

func parseAgentInventory(value any) (AgentInventory, error) {
	object, err := objectValue(value, "inventory")
	if err != nil {
		return AgentInventory{}, err
	}
	if err := requireFields(object, []string{"version", "boot_id", "build_id", "iso_id", "iso_sha256"}, "inventory"); err != nil {
		return AgentInventory{}, err
	}
	version, err := stringValue(object["version"], "inventory")
	if err != nil {
		return AgentInventory{}, err
	}
	bootID, err := stringValue(object["boot_id"], "inventory")
	if err != nil {
		return AgentInventory{}, err
	}
	buildID, err := stringValue(object["build_id"], "inventory")
	if err != nil {
		return AgentInventory{}, err
	}
	isoID, err := stringValue(object["iso_id"], "inventory")
	if err != nil {
		return AgentInventory{}, err
	}
	isoSHA256, err := stringValue(object["iso_sha256"], "inventory")
	if err != nil || !sha256Pattern.MatchString(isoSHA256) {
		return AgentInventory{}, contractError("inventory_value_invalid", "agent.iso_sha256 must be SHA-256")
	}
	return AgentInventory{Version: version, BootID: bootID, BuildID: buildID, ISOID: isoID, ISOSHA256: isoSHA256}, nil
}

func parseMachineInventory(value any) (MachineInventory, error) {
	object, err := objectValue(value, "inventory")
	if err != nil {
		return MachineInventory{}, err
	}
	if err := requireFields(object, []string{"dmi_uuid", "manufacturer", "product_name", "serial_number", "firmware", "memory_bytes", "cpu_arch"}, "inventory"); err != nil {
		return MachineInventory{}, err
	}
	fields := make([]string, 0, 6)
	for _, name := range []string{"dmi_uuid", "manufacturer", "product_name", "serial_number", "firmware", "cpu_arch"} {
		text, err := stringValue(object[name], "inventory")
		if err != nil {
			return MachineInventory{}, err
		}
		fields = append(fields, text)
	}
	if fields[4] != "uefi" && fields[4] != "bios" {
		return MachineInventory{}, contractError("inventory_value_invalid", "machine.firmware is invalid")
	}
	memoryBytes, err := positiveIntegerValue(object["memory_bytes"], "inventory")
	if err != nil {
		return MachineInventory{}, err
	}
	return MachineInventory{
		DMIUUID: fields[0], Manufacturer: fields[1], ProductName: fields[2], SerialNumber: fields[3],
		Firmware: fields[4], MemoryBytes: memoryBytes, CPUArch: fields[5],
	}, nil
}

func parseInterfaceInventory(value any) (InterfaceInventory, error) {
	object, err := objectValue(value, "inventory")
	if err != nil {
		return InterfaceInventory{}, err
	}
	if err := requireFields(object, []string{"name", "mac", "addresses", "route_to_controller"}, "inventory"); err != nil {
		return InterfaceInventory{}, err
	}
	name, err := stringValue(object["name"], "inventory")
	if err != nil {
		return InterfaceInventory{}, err
	}
	mac, err := stringValue(object["mac"], "inventory")
	if err != nil || !macPattern.MatchString(mac) {
		return InterfaceInventory{}, contractError("inventory_value_invalid", "interface.mac is invalid")
	}
	addressesRaw, err := arrayValue(object["addresses"], "inventory")
	if err != nil {
		return InterfaceInventory{}, err
	}
	addresses := make([]string, 0, len(addressesRaw))
	for _, item := range addressesRaw {
		address, err := stringValue(item, "inventory")
		if err != nil {
			return InterfaceInventory{}, err
		}
		addresses = append(addresses, address)
	}
	routed, err := boolValue(object["route_to_controller"], "inventory")
	if err != nil {
		return InterfaceInventory{}, err
	}
	return InterfaceInventory{Name: name, MAC: strings.ToLower(mac), Addresses: addresses, RouteToController: routed}, nil
}

func parseDiskInventory(value any) (DiskInventory, error) {
	object, err := objectValue(value, "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	if err := requireFields(object, []string{"type", "path", "removable", "size_bytes", "model", "serial", "wwn", "filesystem_signatures"}, "inventory"); err != nil {
		return DiskInventory{}, err
	}
	deviceType, err := stringValue(object["type"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	path, err := stringValue(object["path"], "inventory")
	if err != nil || !diskPathPattern.MatchString(path) {
		return DiskInventory{}, contractError("inventory_value_invalid", "disk.path is unsafe")
	}
	removable, err := boolValue(object["removable"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	sizeBytes, err := positiveIntegerValue(object["size_bytes"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	model, err := stringValue(object["model"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	serial, err := optionalStringValue(object["serial"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	wwn, err := optionalStringValue(object["wwn"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	signaturesRaw, err := arrayValue(object["filesystem_signatures"], "inventory")
	if err != nil {
		return DiskInventory{}, err
	}
	signatures := make([]string, 0, len(signaturesRaw))
	for _, item := range signaturesRaw {
		signature, err := stringValue(item, "inventory")
		if err != nil {
			return DiskInventory{}, err
		}
		signatures = append(signatures, signature)
	}
	return DiskInventory{
		Type: deviceType, Path: path, Removable: removable, SizeBytes: sizeBytes, Model: model,
		Serial: serial, WWN: wwn, FilesystemSignatures: signatures,
	}, nil
}

func parseBootMediaInventory(value any) (BootMediaInventory, error) {
	object, err := objectValue(value, "inventory")
	if err != nil {
		return BootMediaInventory{}, err
	}
	if err := requireFields(object, []string{"path", "model", "serial", "wwn"}, "inventory"); err != nil {
		return BootMediaInventory{}, err
	}
	path, err := stringValue(object["path"], "inventory")
	if err != nil || !mediaPathPattern.MatchString(path) {
		return BootMediaInventory{}, contractError("inventory_value_invalid", "boot_media.path is invalid")
	}
	model, err := stringValue(object["model"], "inventory")
	if err != nil {
		return BootMediaInventory{}, err
	}
	serial, err := optionalStringValue(object["serial"], "inventory")
	if err != nil {
		return BootMediaInventory{}, err
	}
	wwn, err := optionalStringValue(object["wwn"], "inventory")
	if err != nil {
		return BootMediaInventory{}, err
	}
	return BootMediaInventory{Path: path, Model: model, Serial: serial, WWN: wwn}, nil
}

func inventoryMap(inventory Inventory) map[string]any {
	interfaces := make([]any, 0, len(inventory.Interfaces))
	for _, item := range inventory.Interfaces {
		addresses := make([]any, 0, len(item.Addresses))
		for _, address := range item.Addresses {
			addresses = append(addresses, address)
		}
		interfaces = append(interfaces, map[string]any{
			"name": item.Name, "mac": item.MAC, "addresses": addresses, "route_to_controller": item.RouteToController,
		})
	}
	disks := make([]any, 0, len(inventory.Disks))
	for _, disk := range inventory.Disks {
		signatures := make([]any, 0, len(disk.FilesystemSignatures))
		for _, signature := range disk.FilesystemSignatures {
			signatures = append(signatures, signature)
		}
		disks = append(disks, map[string]any{
			"type": disk.Type, "path": disk.Path, "removable": disk.Removable, "size_bytes": disk.SizeBytes,
			"model": disk.Model, "serial": pointerValue(disk.Serial), "wwn": pointerValue(disk.WWN),
			"filesystem_signatures": signatures,
		})
	}
	return map[string]any{
		"schema_version": inventory.SchemaVersion,
		"agent": map[string]any{
			"version": inventory.Agent.Version, "boot_id": inventory.Agent.BootID, "build_id": inventory.Agent.BuildID,
			"iso_id": inventory.Agent.ISOID, "iso_sha256": inventory.Agent.ISOSHA256,
		},
		"machine": map[string]any{
			"dmi_uuid": inventory.Machine.DMIUUID, "manufacturer": inventory.Machine.Manufacturer,
			"product_name": inventory.Machine.ProductName, "serial_number": inventory.Machine.SerialNumber,
			"firmware": inventory.Machine.Firmware, "memory_bytes": inventory.Machine.MemoryBytes, "cpu_arch": inventory.Machine.CPUArch,
		},
		"interfaces": interfaces,
		"disks":      disks,
		"boot_media": map[string]any{
			"path": inventory.BootMedia.Path, "model": inventory.BootMedia.Model,
			"serial": pointerValue(inventory.BootMedia.Serial), "wwn": pointerValue(inventory.BootMedia.WWN),
		},
	}
}

func pointerValue(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

// DiskFingerprint matches alt_deploy.install_fingerprint.disk_fingerprint.
func DiskFingerprint(disk DiskInventory) string {
	identity := map[string]any{
		"model": disk.Model, "path": disk.Path, "serial": pointerValue(disk.Serial),
		"size_bytes": disk.SizeBytes, "wwn": pointerValue(disk.WWN),
	}
	canonical, _ := canonicalJSON(identity)
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}
