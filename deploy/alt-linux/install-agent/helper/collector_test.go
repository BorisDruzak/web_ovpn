package helper

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type fakeSystemProbe struct {
	files map[string][]byte
	runs  []string
}

func (probe *fakeSystemProbe) ReadFile(path string) ([]byte, error) {
	value, ok := probe.files[path]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), value...), nil
}

func (probe *fakeSystemProbe) Run(_ context.Context, name string, arguments ...string) ([]byte, error) {
	command := name
	for _, argument := range arguments {
		command += "\x00" + argument
	}
	probe.runs = append(probe.runs, command)
	switch name {
	case "lsblk":
		return []byte(`{"blockdevices":[{"name":"vda","type":"disk","path":"/dev/vda","rm":false,"size":107374182400,"model":"QEMU HARDDISK","serial":"disk-100","wwn":"0x5000000000000100","fstype":null,"mountpoint":null,"children":[]},{"name":"sr0","type":"rom","path":"/dev/sr0","rm":true,"size":10710822912,"model":"ALT ISO","serial":null,"wwn":null,"fstype":"iso9660","mountpoint":"/image","children":[]}]}`), nil
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
	probe := &fakeSystemProbe{files: map[string][]byte{
		"/usr/share/alt-install/source_iso.json": []byte(`{"schema_version":1,"iso_id":"alt-kworkstation-11.4-install-x86_64","iso_sha256":"2529f98bca03a652709434a6a17cd4aac5df20c0793927abdf784e8f9388243a"}`),
		"/usr/share/alt-install/build-id":        []byte("pr2\n"),
		"/proc/sys/kernel/random/boot_id":        []byte("boot-100\n"),
		"/proc/cmdline":                          []byte("quiet sosnadmin.controller=http://192.0.2.1:18089\n"),
		"/proc/meminfo":                          []byte("MemTotal:        8388608 kB\n"),
		"/sys/class/dmi/id/product_uuid":         []byte("11111111-2222-3333-4444-555555555555\n"),
		"/sys/class/dmi/id/sys_vendor":           []byte("QEMU\n"),
		"/sys/class/dmi/id/product_name":         []byte("Standard PC\n"),
		"/sys/class/dmi/id/product_serial":       []byte("vm-100\n"),
		"/sys/firmware/efi/fw_platform_size":     []byte("64\n"),
	}}

	got, err := collectSystemInventory(context.Background(), probe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("collected inventory mismatch\n got: %s\nwant: %s", got, want)
	}
	wantRuns := []string{
		"lsblk\x00--json\x00--bytes\x00--output\x00NAME,TYPE,PATH,RM,SIZE,MODEL,SERIAL,WWN,FSTYPE,MOUNTPOINT",
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

	_, bootMedia, err := inventoryDisks(devices)
	if err != nil {
		t.Fatal(err)
	}
	if bootMedia.Path != "/dev/sdb" || bootMedia.Model != "USB ISO" || bootMedia.Serial == nil || *bootMedia.Serial != serial {
		t.Fatalf("boot media identity = %+v, want top-level /dev/sdb ancestor", bootMedia)
	}
}
