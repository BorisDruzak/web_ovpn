package helper

const standardOfficeV1MinimumDiskBytes int64 = 53687091200

type DiskPreflightInput struct {
	Plan              []byte
	RecordedInventory []byte
	CurrentInventory  []byte
}

type DiskPreflightResult struct {
	DiskPath         string `json:"disk_path"`
	DiskFingerprint  string `json:"disk_fingerprint"`
	WeakDiskIdentity bool   `json:"weak_disk_identity"`
}

// DiskPreflight is a pure comparison: it has no filesystem or block-device
// handle and therefore cannot write the selected target.
func DiskPreflight(input DiskPreflightInput) (DiskPreflightResult, error) {
	plan, err := exactCanonicalPlan(input.Plan)
	if err != nil {
		return DiskPreflightResult{}, err
	}
	recorded, err := ParseInventory(input.RecordedInventory)
	if err != nil {
		return DiskPreflightResult{}, err
	}
	current, err := ParseInventory(input.CurrentInventory)
	if err != nil {
		return DiskPreflightResult{}, err
	}
	recordedCanonical, err := canonicalJSON(inventoryMap(recorded))
	if err != nil {
		return DiskPreflightResult{}, err
	}
	recordedDigest := sha256Hex(recordedCanonical)
	if recordedDigest != plan.InventorySHA256 {
		return DiskPreflightResult{}, contractError("plan_inventory_mismatch", "recorded inventory binding differs")
	}
	if _, _, err := matchPlanInventory(plan, recorded); err != nil {
		return DiskPreflightResult{}, err
	}
	if plan.Firmware != "uefi" || current.Machine.Firmware != "uefi" || current.Machine.Firmware != recorded.Machine.Firmware {
		return DiskPreflightResult{}, contractError("preflight_firmware_mismatch", "UEFI firmware state changed")
	}
	if !bootMediaEqual(recorded.BootMedia, current.BootMedia) {
		return DiskPreflightResult{}, contractError("preflight_boot_media_mismatch", "boot media identity changed")
	}
	candidates, err := eligiblePreflightDisks(plan, current)
	if err != nil {
		return DiskPreflightResult{}, err
	}
	if len(candidates) != 1 {
		return DiskPreflightResult{}, contractError("preflight_disk_ambiguous", "exactly one eligible disk is required")
	}
	selected := candidates[0]
	if !targetDiskMatches(plan.TargetDisk, selected) {
		return DiskPreflightResult{}, contractError("preflight_disk_mismatch", "selected disk identity changed")
	}
	routed := routedInterfaces(current)
	if len(routed) != 1 || routed[0].Name != plan.NetworkInterface.Name || routed[0].MAC != plan.NetworkInterface.MAC {
		return DiskPreflightResult{}, contractError("preflight_network_mismatch", "routed interface identity changed")
	}
	return DiskPreflightResult{
		DiskPath: selected.Path, DiskFingerprint: DiskFingerprint(selected),
		WeakDiskIdentity: selected.Serial == nil && selected.WWN == nil,
	}, nil
}

func eligiblePreflightDisks(plan InstallPlan, inventory Inventory) ([]DiskInventory, error) {
	if plan.ProfileID != "standard-office" || plan.ProfileVersion != 1 {
		return nil, contractError("preflight_profile_unsupported", "plan profile is not supported by helper V1")
	}
	physicalCount := 0
	result := make([]DiskInventory, 0, len(inventory.Disks))
	for _, disk := range inventory.Disks {
		if disk.Type != "disk" {
			continue
		}
		physicalCount++
		if disk.Path == inventory.BootMedia.Path {
			return nil, contractError("preflight_disk_is_boot_media", "boot media cannot be a target disk")
		}
		if disk.Removable {
			return nil, contractError("preflight_disk_removable", "removable physical disk is not eligible")
		}
		if disk.SizeBytes >= standardOfficeV1MinimumDiskBytes {
			result = append(result, disk)
		}
	}
	if physicalCount == 0 {
		return nil, contractError("preflight_disk_missing", "no physical disk is available")
	}
	if len(result) == 0 {
		return nil, contractError("preflight_disk_too_small", "no disk meets the profile minimum")
	}
	return result, nil
}

func bootMediaEqual(left, right BootMediaInventory) bool {
	return left.Path == right.Path && left.Model == right.Model &&
		equalOptionalString(left.Serial, right.Serial) && equalOptionalString(left.WWN, right.WWN)
}
