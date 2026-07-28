package helper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

type fakeSystemProbe struct {
	files       map[string][]byte
	directories map[string][]string
	errors      map[string]error
	runs        []string
}

func (probe *fakeSystemProbe) ReadDirectory(path string) ([]string, error) {
	entries, ok := probe.directories[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]string(nil), entries...), nil
}

func (probe *fakeSystemProbe) ReadFile(path string) ([]byte, error) {
	if err, ok := probe.errors[path]; ok {
		return nil, err
	}
	value, ok := probe.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

func TestCollectBlockDevicesKeepsMountedPartitionUnderPhysicalParent(t *testing.T) {
	probe := &fakeSystemProbe{directories: map[string][]string{
		"/sys/class/block": {"sdb", "sdb1"},
	}, files: map[string][]byte{
		"/proc/self/mountinfo":              []byte("1 0 8:17 / /image ro - iso9660 /dev/sdb1 ro\n"),
		"/sys/class/block/sdb/dev":          []byte("8:16\n"),
		"/sys/class/block/sdb/size":         []byte("31250000\n"),
		"/sys/class/block/sdb/removable":    []byte("1\n"),
		"/sys/class/block/sdb/device/model": []byte("USB\n"),
		"/sys/class/block/sdb1/partition":   []byte("1\n"),
		"/sys/class/block/sdb1/dev":         []byte("8:17\n"),
		"/sys/class/block/sdb1/size":        []byte("31200000\n"),
	}}

	devices, err := collectBlockDevices(context.Background(), probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].Path != "/dev/sdb" || len(devices[0].Children) != 1 || devices[0].Children[0].Mountpoint == nil || *devices[0].Children[0].Mountpoint != "/image" {
		t.Fatalf("unexpected block topology: %+v", devices)
	}
}

func TestCollectBlockDevicesRejectsUnsupportedBootMediaTopology(t *testing.T) {
	probe := &fakeSystemProbe{directories: map[string][]string{
		"/sys/class/block": {"dm-0"},
	}, files: map[string][]byte{
		"/proc/self/mountinfo":      []byte("1 0 253:0 / /image ro - squashfs /dev/dm-0 ro\n"),
		"/sys/class/block/dm-0/dev": []byte("253:0\n"),
	}}

	if _, err := collectBlockDevices(context.Background(), probe); err == nil {
		t.Fatal("unsupported dm boot media must fail closed")
	}
}

func TestSysfsBlockTypeRejectsUnreadableType(t *testing.T) {
	probe := &fakeSystemProbe{errors: map[string]error{
		"/sys/class/block/sda/device/type": errors.New("I/O error"),
	}}

	if _, err := sysfsBlockType(probe, "sda"); err == nil {
		t.Fatal("unreadable sysfs type must not use name fallback")
	}
}

func TestReadBlockDeviceHandlesOptionalIdentityReadErrors(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    string
		err     error
		wantErr bool
	}{
		{"serial missing", "/sys/class/block/sda/device/serial", os.ErrNotExist, false},
		{"wwid missing", "/sys/class/block/sda/device/wwid", os.ErrNotExist, false},
		{"serial unavailable", "/sys/class/block/sda/device/serial", syscall.ENXIO, false},
		{"wwid unavailable", "/sys/class/block/sda/device/wwid", syscall.ENXIO, false},
		{"serial I/O failure", "/sys/class/block/sda/device/serial", syscall.EIO, true},
		{"wwid I/O failure", "/sys/class/block/sda/device/wwid", syscall.EIO, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			probe := &fakeSystemProbe{
				files: map[string][]byte{
					"/sys/class/block/sda/dev":       []byte("8:0\n"),
					"/sys/class/block/sda/size":      []byte("2097152\n"),
					"/sys/class/block/sda/removable": []byte("0\n"),
				},
				errors: map[string]error{test.path: test.err},
			}

			device, err := readBlockDevice(context.Background(), probe, "sda", "", nil)
			if test.wantErr {
				if err == nil {
					t.Fatal("identity I/O failure must reject disk")
				}
				return
			}
			if err != nil {
				t.Fatalf("optional identity read should not reject disk: %v", err)
			}
			if device.Serial != nil || device.WWN != nil {
				t.Fatalf("optional identities = serial=%v wwid=%v, want absent", device.Serial, device.WWN)
			}
		})
	}
}

func TestReadBlockDeviceUsesUnknownModelWhenSysfsModelIsAbsent(t *testing.T) {
	probe := &fakeSystemProbe{files: map[string][]byte{
		"/sys/class/block/vda/dev":       []byte("252:0\n"),
		"/sys/class/block/vda/size":      []byte("2097152\n"),
		"/sys/class/block/vda/removable": []byte("0\n"),
	}}

	device, err := readBlockDevice(context.Background(), probe, "vda", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if device.Model != "unknown" {
		t.Fatalf("model = %q, want unknown", device.Model)
	}
}

func TestReadBlockDeviceUsesTopLevelVirtioIdentityFallback(t *testing.T) {
	probe := &fakeSystemProbe{files: map[string][]byte{
		"/sys/class/block/vda/dev":       []byte("252:0\n"),
		"/sys/class/block/vda/size":      []byte("2097152\n"),
		"/sys/class/block/vda/removable": []byte("0\n"),
		"/sys/class/block/vda/serial":    []byte("ALT-QEMU-DRYRUN\n"),
	}}

	device, err := readBlockDevice(context.Background(), probe, "vda", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if device.Serial == nil || *device.Serial != "ALT-QEMU-DRYRUN" {
		t.Fatalf("serial = %v, want virtio fallback identity", device.Serial)
	}
}

func (probe *fakeSystemProbe) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	command := name
	for _, argument := range arguments {
		command += "\x00" + argument
	}
	probe.runs = append(probe.runs, command)
	switch name {
	case "ip":
		if len(arguments) >= 2 && arguments[1] == "address" {
			return []byte(`[{"ifname":"lo","address":"00:00:00:00:00:00","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},{"ifname":"enp6s18","address":"52:54:00:12:34:57","addr_info":[{"local":"192.0.2.11","prefixlen":24}]}]`), nil
		}
		return []byte(`[{"dst":"192.0.2.1","dev":"enp6s18","prefsrc":"192.0.2.11"}]`), nil
	default:
		return nil, os.ErrNotExist
	}
}

func TestSystemCollectorProducesCanonicalPR3InventoryUsingReadOnlyProbes(t *testing.T) {
	rawVector, err := os.ReadFile(filepath.Join("testdata", "v1", "golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		InventoryCanonicalB64 string `json:"inventory_canonical_b64"`
	}
	if err := json.Unmarshal(rawVector, &vector); err != nil {
		t.Fatal(err)
	}
	want, err := base64.StdEncoding.DecodeString(vector.InventoryCanonicalB64)
	if err != nil {
		t.Fatal(err)
	}
	probe := &fakeSystemProbe{directories: map[string][]string{
		"/sys/class/block": {"vda", "sr0", "loop0"},
	}, files: map[string][]byte{
		"/usr/share/alt-install/source_iso.json":        []byte(`{"schema_version":1,"iso_id":"alt-kworkstation-11.4-install-x86_64","iso_sha256":"2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf784e8f9388243a"}`),
		"/usr/share/alt-install/managed_iso_size_bytes": []byte("10710822912\n"),
		"/usr/share/alt-install/build-id":               []byte("pr2\n"),
		"/proc/sys/kernel/random/boot_id":               []byte("boot-100\n"),
		"/proc/cmdline":                                 []byte("quiet sosnadmin.controller=http://192.0.2.1:18089\n"),
		"/proc/meminfo":                                 []byte("MemTotal:        8388608 kB\n"),
		"/sys/class/dmi/id/product_uuid":                []byte("11111111-2222-3333-4444-555555555555\n"),
		"/sys/class/dmi/id/sys_vendor":                  []byte("QEMU\n"),
		"/sys/class/dmi/id/product_name":                []byte("Standard PC\n"),
		"/sys/class/dmi/id/product_serial":              []byte("vm-100\n"),
		"/sys/firmware/efi/fw_platform_size":            []byte("64\n"),
		"/proc/self/mountinfo":                          []byte("36 25 11:0 / /image ro - iso9660 /dev/sr0 ro\n"),
		"/sys/class/block/vda/dev":                      []byte("252:0\n"),
		"/sys/class/block/vda/size":                     []byte("209715200\n"),
		"/sys/class/block/vda/removable":                []byte("0\n"),
		"/sys/class/block/vda/device/model":             []byte("QEMU HARDDISK\n"),
		"/sys/class/block/vda/device/serial":            []byte("disk-100\n"),
		"/sys/class/block/vda/device/wwid":              []byte("0x5000000000000100\n"),
		"/sys/class/block/sr0/dev":                      []byte("11:0\n"),
		"/sys/class/block/sr0/size":                     []byte("20919576\n"),
		"/sys/class/block/sr0/removable":                []byte("1\n"),
		"/sys/class/block/sr0/device/type":              []byte("5\n"),
		"/sys/class/block/sr0/device/model":             []byte("ALT ISO\n"),
		"/sys/class/block/loop0/dev":                    []byte("7:0\n"),
	}}

	got, err := collectSystemInventory(context.Background(), probe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("collected inventory mismatch\n got: %s\nwant: %s", got, want)
	}
	wantRuns := []string{
		"/usr/sbin/blkid\x00-o\x00export\x00/dev/sr0",
		"/usr/sbin/blkid\x00-o\x00export\x00/dev/vda",
		"ip\x00-j\x00address\x00show",
		"ip\x00-j\x00route\x00get\x00192.0.2.1",
	}
	if !reflect.DeepEqual(probe.runs, wantRuns) {
		t.Fatalf("probe commands = %#v, want %#v", probe.runs, wantRuns)
	}
}

func TestInventoryDisksUsesBootMediaTopLevelAncestor(t *testing.T) {
	serial := "usb-media"
	mountpoint := "/image"
	devices := []blockDevice{
		{Name: "vda", Type: "disk", Path: "/dev/vda", Size: flexibleInt64(107374182400), Model: "target"},
		{
			Name: "sdb", Type: "disk", Path: "/dev/sdb", Removable: true,
			Size: flexibleInt64(16000000000), Model: "USB ISO", Serial: &serial,
			Children: []blockDevice{{
				Name: "sdb1", Type: "part", Path: "/dev/sdb1",
				Size: flexibleInt64(15900000000), Mountpoint: &mountpoint,
			}},
		},
	}

	_, bootMedia, err := inventoryDisks(devices, 16_000_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if bootMedia.Path != "/dev/sdb" || bootMedia.Model != "USB ISO" || bootMedia.Serial == nil || *bootMedia.Serial != serial {
		t.Fatalf("boot media identity = %+v, want top-level /dev/sdb ancestor", bootMedia)
	}
}

func TestInventoryDisksUsesExactSizeROMWithoutImageMount(t *testing.T) {
	const managedISOSize = 10_711_990_272
	devices := []blockDevice{
		{Name: "vda", Type: "disk", Path: "/dev/vda", Size: flexibleInt64(64 * 1024 * 1024 * 1024), Model: "target"},
		{Name: "sr0", Type: "rom", Path: "/dev/sr0", Removable: true, Size: flexibleInt64(managedISOSize), Model: "ALT ISO"},
		{Name: "sr1", Type: "rom", Path: "/dev/sr1", Removable: true, Size: flexibleInt64(1 * 1024 * 1024 * 1024), Model: "other"},
	}

	_, bootMedia, err := inventoryDisks(devices, managedISOSize)
	if err != nil {
		t.Fatal(err)
	}
	if bootMedia.Path != "/dev/sr0" || bootMedia.Model != "ALT ISO" {
		t.Fatalf("boot media = %+v, want /dev/sr0", bootMedia)
	}
}

func TestInventoryDisksRejectsNonUniqueROMFallback(t *testing.T) {
	const managedISOSize = 10_711_990_272
	for _, test := range []struct {
		name    string
		devices []blockDevice
		want    string
	}{
		{
			name: "no matching ROM",
			devices: []blockDevice{
				{Name: "vda", Type: "disk", Path: "/dev/vda", Size: flexibleInt64(managedISOSize), Model: "target"},
				{Name: "sr1", Type: "rom", Path: "/dev/sr1", Removable: true, Size: flexibleInt64(managedISOSize - 512), Model: "other"},
			},
			want: "inventory_boot_media_missing",
		},
		{
			name: "multiple matching ROMs",
			devices: []blockDevice{
				{Name: "sr0", Type: "rom", Path: "/dev/sr0", Removable: true, Size: flexibleInt64(managedISOSize), Model: "ALT ISO"},
				{Name: "sr1", Type: "rom", Path: "/dev/sr1", Removable: true, Size: flexibleInt64(managedISOSize), Model: "duplicate"},
			},
			want: "inventory_boot_media_ambiguous",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := inventoryDisks(test.devices, managedISOSize)
			if ErrorCode(err) != test.want {
				t.Fatalf("error code = %q, want %q (error: %v)", ErrorCode(err), test.want, err)
			}
		})
	}
}

func TestBusyBoxNetworkParsersCollectRouteAndAddresses(t *testing.T) {
	addresses, err := parseBusyBoxAddresses("1: lo    inet 127.0.0.1/8 scope host lo\n2: enp6s18    inet 192.168.100.50/24 brd 192.168.100.255 scope global enp6s18\n2: enp6s18    inet6 2001:db8::50/64 scope global\n")
	if err != nil {
		t.Fatal(err)
	}
	macs, err := parseBusyBoxLinks("1: lo: <LOOPBACK> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000    link/loopback 00:00:00:00:00:00\n2: enp6s18: <BROADCAST> mtu 1500 qdisc fq state UP mode DEFAULT group default qlen 1000    link/ether 52:54:00:12:34:57 brd ff:ff:ff:ff:ff:ff\n")
	if err != nil {
		t.Fatal(err)
	}
	route, err := parseBusyBoxRouteToHost("default via 192.168.100.2 dev enp6s18\n192.168.100.0/24 dev enp6s18 scope link src 192.168.100.50\n", "192.168.100.17")
	if err != nil {
		t.Fatal(err)
	}
	document := []ipInterface{{Name: "enp6s18", MAC: macs["enp6s18"], Addresses: addresses["enp6s18"]}}
	interfaces, err := inventoryInterfaces(document, route)
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 1 || !interfaces[0].RouteToController || interfaces[0].MAC != "52:54:00:12:34:57" || !reflect.DeepEqual(interfaces[0].Addresses, []string{"192.168.100.50/24", "2001:db8::50/64"}) {
		t.Fatalf("interfaces = %+v", interfaces)
	}
}

func TestBusyBoxRouteToHostUsesTheMostSpecificRoute(t *testing.T) {
	route, err := parseBusyBoxRouteToHost("default via 192.0.2.1 dev eth0\n192.168.100.17/32 dev eth1 scope link\n", "192.168.100.17")
	if err != nil || route != "eth1" {
		t.Fatalf("route = %q, %v; want eth1", route, err)
	}
}

func TestBusyBoxRouteToHostRejectsAmbiguousRoutes(t *testing.T) {
	if _, err := parseBusyBoxRouteToHost("192.168.100.0/24 dev eth0\n192.168.100.0/24 dev eth1\n", "192.168.100.17"); err == nil {
		t.Fatal("ambiguous controller route must fail closed")
	}
}

func TestReadPositiveIntRequiresCanonicalDecimal(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte("10710822912\n"),
		[]byte("+10710822912\n"),
		[]byte("0010710822912\n"),
		[]byte("10710822912 \n"),
		[]byte("10710822912"),
		[]byte("0\n"),
	} {
		probe := &fakeSystemProbe{files: map[string][]byte{"/size": raw}}
		_, err := readPositiveInt(probe, "/size")
		valid := string(raw) == "10710822912\n"
		if (err == nil) != valid {
			t.Fatalf("readPositiveInt(%q) error = %v, valid = %t", raw, err, valid)
		}
	}
}
