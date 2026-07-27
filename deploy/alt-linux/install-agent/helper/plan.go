package helper

import (
	"bytes"
	"regexp"
	"time"
)

var (
	sessionPattern  = regexp.MustCompile(`^install-[A-Za-z0-9-]{4,64}$`)
	hostnamePattern = regexp.MustCompile(`^alt-install-[a-z0-9-]{1,63}$`)
)

type PlanTargetDisk struct {
	Path        string
	SizeBytes   int64
	Model       string
	Serial      *string
	WWN         *string
	Fingerprint string
}

type PlanNetworkInterface struct {
	Name string
	MAC  string
}

type PlanDiskLayout struct {
	WipeMode        string
	SwapMiB         int64
	Filesystem      string
	BtrfsMinimumMiB int64
	Grow            bool
	Subvolumes      map[string]string
}

type InstallPlan struct {
	SchemaVersion     int64
	SessionID         string
	Revision          int64
	InventorySHA256   string
	ProfileID         string
	ProfileVersion    int64
	ISOID             string
	ISOSHA256         string
	Firmware          string
	TargetDisk        PlanTargetDisk
	NetworkInterface  PlanNetworkInterface
	DiskLayout        PlanDiskLayout
	PackageSet        string
	TemporaryHostname string
	ApprovedAt        string
	ExpiresAt         string
}

func parsePlan(raw []byte) (InstallPlan, []byte, error) {
	value, err := parseStrictJSON(raw)
	if err != nil {
		return InstallPlan{}, nil, err
	}
	root, err := objectValue(value, "plan")
	if err != nil {
		return InstallPlan{}, nil, err
	}
	fields := []string{
		"schema_version", "session_id", "revision", "inventory_sha256", "profile_id", "profile_version",
		"iso_id", "iso_sha256", "firmware", "target_disk", "network_interface", "disk_layout",
		"package_set", "temporary_hostname", "approved_at", "expires_at",
	}
	if err := requireFields(root, fields, "plan"); err != nil {
		return InstallPlan{}, nil, err
	}
	schemaVersion, err := positiveIntegerValue(root["schema_version"], "plan")
	if err != nil {
		return InstallPlan{}, nil, err
	}
	if schemaVersion != 1 {
		return InstallPlan{}, nil, contractError("plan_schema_unsupported", "plan schema_version must be 1")
	}
	revision, err := positiveIntegerValue(root["revision"], "plan")
	if err != nil {
		return InstallPlan{}, nil, err
	}
	profileVersion, err := positiveIntegerValue(root["profile_version"], "plan")
	if err != nil {
		return InstallPlan{}, nil, err
	}
	stringsByName := make(map[string]string, 10)
	for _, name := range []string{
		"session_id", "inventory_sha256", "profile_id", "iso_id", "iso_sha256", "firmware",
		"package_set", "temporary_hostname", "approved_at", "expires_at",
	} {
		text, err := stringValue(root[name], "plan")
		if err != nil {
			return InstallPlan{}, nil, err
		}
		stringsByName[name] = text
	}
	if !sessionPattern.MatchString(stringsByName["session_id"]) {
		return InstallPlan{}, nil, contractError("plan_value_invalid", "plan session_id is invalid")
	}
	if !hostnamePattern.MatchString(stringsByName["temporary_hostname"]) {
		return InstallPlan{}, nil, contractError("plan_value_invalid", "plan temporary_hostname is invalid")
	}
	if !sha256Pattern.MatchString(stringsByName["inventory_sha256"]) || !sha256Pattern.MatchString(stringsByName["iso_sha256"]) {
		return InstallPlan{}, nil, contractError("plan_value_invalid", "plan SHA-256 value is invalid")
	}
	approvedAt, err := time.Parse(time.RFC3339, stringsByName["approved_at"])
	if err != nil {
		return InstallPlan{}, nil, contractError("plan_timestamp_invalid", "plan approved_at is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339, stringsByName["expires_at"])
	if err != nil {
		return InstallPlan{}, nil, contractError("plan_timestamp_invalid", "plan expires_at is invalid")
	}
	if !expiresAt.After(approvedAt) {
		return InstallPlan{}, nil, contractError("plan_expiry_invalid", "plan expiry must follow approval")
	}
	targetDisk, err := parsePlanTargetDisk(root["target_disk"])
	if err != nil {
		return InstallPlan{}, nil, err
	}
	networkInterface, err := parsePlanNetwork(root["network_interface"])
	if err != nil {
		return InstallPlan{}, nil, err
	}
	diskLayout, err := parsePlanDiskLayout(root["disk_layout"])
	if err != nil {
		return InstallPlan{}, nil, err
	}
	plan := InstallPlan{
		SchemaVersion: schemaVersion, SessionID: stringsByName["session_id"], Revision: revision,
		InventorySHA256: stringsByName["inventory_sha256"], ProfileID: stringsByName["profile_id"],
		ProfileVersion: profileVersion, ISOID: stringsByName["iso_id"], ISOSHA256: stringsByName["iso_sha256"],
		Firmware: stringsByName["firmware"], TargetDisk: targetDisk, NetworkInterface: networkInterface,
		DiskLayout: diskLayout, PackageSet: stringsByName["package_set"], TemporaryHostname: stringsByName["temporary_hostname"],
		ApprovedAt: stringsByName["approved_at"], ExpiresAt: stringsByName["expires_at"],
	}
	canonical, err := canonicalJSON(planMap(plan))
	if err != nil {
		return InstallPlan{}, nil, err
	}
	return plan, canonical, nil
}

func parsePlanTargetDisk(value any) (PlanTargetDisk, error) {
	object, err := objectValue(value, "plan")
	if err != nil {
		return PlanTargetDisk{}, err
	}
	if err := requireFields(object, []string{"path", "size_bytes", "model", "serial", "wwn", "fingerprint"}, "plan"); err != nil {
		return PlanTargetDisk{}, err
	}
	path, err := stringValue(object["path"], "plan")
	if err != nil || !diskPathPattern.MatchString(path) {
		return PlanTargetDisk{}, contractError("plan_value_invalid", "plan target disk path is invalid")
	}
	size, err := positiveIntegerValue(object["size_bytes"], "plan")
	if err != nil {
		return PlanTargetDisk{}, err
	}
	model, err := stringValue(object["model"], "plan")
	if err != nil {
		return PlanTargetDisk{}, err
	}
	serial, err := optionalStringValue(object["serial"], "plan")
	if err != nil {
		return PlanTargetDisk{}, err
	}
	wwn, err := optionalStringValue(object["wwn"], "plan")
	if err != nil {
		return PlanTargetDisk{}, err
	}
	fingerprint, err := stringValue(object["fingerprint"], "plan")
	if err != nil || !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(fingerprint) {
		return PlanTargetDisk{}, contractError("plan_value_invalid", "plan target disk fingerprint is invalid")
	}
	return PlanTargetDisk{Path: path, SizeBytes: size, Model: model, Serial: serial, WWN: wwn, Fingerprint: fingerprint}, nil
}

func parsePlanNetwork(value any) (PlanNetworkInterface, error) {
	object, err := objectValue(value, "plan")
	if err != nil {
		return PlanNetworkInterface{}, err
	}
	if err := requireFields(object, []string{"name", "mac"}, "plan"); err != nil {
		return PlanNetworkInterface{}, err
	}
	name, err := stringValue(object["name"], "plan")
	if err != nil {
		return PlanNetworkInterface{}, err
	}
	mac, err := stringValue(object["mac"], "plan")
	if err != nil || !macPattern.MatchString(mac) {
		return PlanNetworkInterface{}, contractError("plan_value_invalid", "plan network MAC is invalid")
	}
	return PlanNetworkInterface{Name: name, MAC: regexp.MustCompile(`[A-F]`).ReplaceAllStringFunc(mac, func(value string) string {
		return string(value[0] + ('a' - 'A'))
	})}, nil
}

func parsePlanDiskLayout(value any) (PlanDiskLayout, error) {
	object, err := objectValue(value, "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	if err := requireFields(object, []string{"wipe_mode", "swap_mib", "filesystem", "btrfs_minimum_mib", "grow", "subvolumes"}, "plan"); err != nil {
		return PlanDiskLayout{}, err
	}
	wipeMode, err := stringValue(object["wipe_mode"], "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	swapMiB, err := positiveIntegerValue(object["swap_mib"], "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	filesystem, err := stringValue(object["filesystem"], "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	btrfsMinimumMiB, err := positiveIntegerValue(object["btrfs_minimum_mib"], "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	grow, err := boolValue(object["grow"], "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	subvolumeObject, err := objectValue(object["subvolumes"], "plan")
	if err != nil {
		return PlanDiskLayout{}, err
	}
	if len(subvolumeObject) == 0 || len(subvolumeObject) > maxArrayItems {
		return PlanDiskLayout{}, contractError("json_limit_exceeded", "plan subvolumes has invalid size")
	}
	subvolumes := make(map[string]string, len(subvolumeObject))
	for name, rawMount := range subvolumeObject {
		if name == "" {
			return PlanDiskLayout{}, contractError("plan_value_invalid", "plan subvolume name is invalid")
		}
		mount, err := stringValue(rawMount, "plan")
		if err != nil {
			return PlanDiskLayout{}, err
		}
		subvolumes[name] = mount
	}
	return PlanDiskLayout{
		WipeMode: wipeMode, SwapMiB: swapMiB, Filesystem: filesystem,
		BtrfsMinimumMiB: btrfsMinimumMiB, Grow: grow, Subvolumes: subvolumes,
	}, nil
}

func planMap(plan InstallPlan) map[string]any {
	subvolumes := make(map[string]any, len(plan.DiskLayout.Subvolumes))
	for name, mount := range plan.DiskLayout.Subvolumes {
		subvolumes[name] = mount
	}
	return map[string]any{
		"schema_version": plan.SchemaVersion, "session_id": plan.SessionID, "revision": plan.Revision,
		"inventory_sha256": plan.InventorySHA256, "profile_id": plan.ProfileID, "profile_version": plan.ProfileVersion,
		"iso_id": plan.ISOID, "iso_sha256": plan.ISOSHA256, "firmware": plan.Firmware,
		"target_disk": map[string]any{
			"path": plan.TargetDisk.Path, "size_bytes": plan.TargetDisk.SizeBytes, "model": plan.TargetDisk.Model,
			"serial": pointerValue(plan.TargetDisk.Serial), "wwn": pointerValue(plan.TargetDisk.WWN),
			"fingerprint": plan.TargetDisk.Fingerprint,
		},
		"network_interface": map[string]any{"name": plan.NetworkInterface.Name, "mac": plan.NetworkInterface.MAC},
		"disk_layout": map[string]any{
			"wipe_mode": plan.DiskLayout.WipeMode, "swap_mib": plan.DiskLayout.SwapMiB,
			"filesystem": plan.DiskLayout.Filesystem, "btrfs_minimum_mib": plan.DiskLayout.BtrfsMinimumMiB,
			"grow": plan.DiskLayout.Grow, "subvolumes": subvolumes,
		},
		"package_set": plan.PackageSet, "temporary_hostname": plan.TemporaryHostname,
		"approved_at": plan.ApprovedAt, "expires_at": plan.ExpiresAt,
	}
}

func exactCanonicalPlan(raw []byte) (InstallPlan, error) {
	plan, canonical, err := parsePlan(raw)
	if err != nil {
		return InstallPlan{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return InstallPlan{}, contractError("plan_not_canonical", "plan bytes are not canonical")
	}
	return plan, nil
}
