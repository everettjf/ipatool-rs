// Public, synthetic license-relationship controls for UnfairPlay b3a7a432 (MIT).
package fairplay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"howett.net/plist"
)

func TestRustLicenseAssociationPublicVectors(t *testing.T) {
	dir := os.Getenv("IPATOOL_PUBLIC_VECTOR_DIR")
	if dir == "" {
		t.Skip("set IPATOOL_PUBLIC_VECTOR_DIR for public fixture export")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("output directory must be absolute")
	}
	const root = "Payload/A.app/"
	const a = "SC_Info/A.sinf"
	const b = "SC_Info/B.sinf"
	const target = "PlugIns/B.appex/SC_Info/B.sinf"
	type sample struct {
		name    string
		entries map[string][]byte
	}
	var samples []sample
	add := func(name string, sources, targets []string, entries map[string][]byte) {
		entries[root+"SC_Info/Manifest.plist"] = syntheticLicenseManifest(t, sources, targets)
		samples = append(samples, sample{name, entries})
	}
	add("missing replica", []string{a}, []string{target}, map[string][]byte{root + a: []byte("source")})
	add("identical replica", []string{a}, []string{target}, map[string][]byte{root + a: []byte("source"), root + target: []byte("source")})
	add("different replica", []string{a}, []string{target}, map[string][]byte{root + a: []byte("source"), root + target: []byte("other")})
	add("duplicate target", []string{a}, []string{target, target}, map[string][]byte{root + a: []byte("source")})
	add("duplicate source", []string{a, a}, []string{target}, map[string][]byte{root + a: []byte("source")})
	for name, path := range map[string]string{"traversal": "../SC_Info/B.sinf", "absolute": "/SC_Info/B.sinf", "backslash": "SC_Info\\B.sinf", "noncanonical": "PlugIns/./B.appex/SC_Info/B.sinf", "wrong suffix": "SC_Info/B.supf", "no license directory": "Resources/B.sinf", "empty path": ""} {
		add(name, []string{a}, []string{path}, map[string][]byte{root + a: []byte("source")})
	}
	add("missing source", []string{a}, []string{target}, map[string][]byte{})
	add("no source declaration", nil, []string{target}, map[string][]byte{root + a: []byte("source")})
	add("multiple exact sources", []string{b, a}, []string{target, a}, map[string][]byte{root + a: []byte("first"), root + b: []byte("second"), root + target: []byte("second")})
	add("ambiguous missing replica", []string{a, b}, []string{target}, map[string][]byte{root + a: []byte("first"), root + b: []byte("second")})
	add("identical sources choose sorted", []string{b, a}, []string{target}, map[string][]byte{root + a: []byte("same"), root + b: []byte("same")})
	add("independent sources", []string{b, a}, nil, map[string][]byte{root + a: []byte("first"), root + b: []byte("second")})
	add("self source keeps identity", []string{b, a}, []string{a}, map[string][]byte{root + a: []byte("first"), root + b: []byte("second")})
	for _, prefix := range []string{"/Payload/A.app/", "Payload//A.app/", "../A.app/", "Payload\\A.app/"} {
		samples = append(samples, sample{"invalid root " + prefix, map[string][]byte{prefix + "SC_Info/Manifest.plist": syntheticLicenseManifest(t, []string{a}, []string{target}), prefix + a: []byte("source")}})
	}
	samples = append(samples, sample{"malformed manifest", map[string][]byte{root + "SC_Info/Manifest.plist": []byte("not a plist")}})
	binaryManifest, err := plist.Marshal(macOSSINFManifest{SINFPaths: []string{a}, SINFReplicationPaths: []string{target}}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	samples = append(samples, sample{"binary manifest", map[string][]byte{root + "SC_Info/Manifest.plist": binaryManifest, root + a: []byte("source")}})
	add("uppercase source suffix", []string{"SC_Info/A.SINF"}, []string{target}, map[string][]byte{root + "SC_Info/A.SINF": []byte("source")})
	for _, conflict := range []bool{false, true} {
		outerTarget := a
		name := "independent nested manifests"
		if conflict {
			outerTarget = target
			name = "nested manifest target conflict"
		}
		samples = append(samples, sample{name, map[string][]byte{
			root + a: []byte("same"), root + target: []byte("same"),
			root + "SC_Info/Manifest.plist":                 syntheticLicenseManifest(t, []string{a}, []string{outerTarget}),
			root + "PlugIns/B.appex/SC_Info/Manifest.plist": syntheticLicenseManifest(t, []string{"SC_Info/B.sinf"}, []string{"SC_Info/B.sinf"}),
		}})
	}
	wrongType, err := plist.Marshal(map[string]any{"SinfPaths": []int{1}, "SinfReplicationPaths": []string{target}}, plist.XMLFormat)
	if err != nil {
		t.Fatal(err)
	}
	samples = append(samples, sample{"typed source declaration", map[string][]byte{root + "SC_Info/Manifest.plist": wrongType}})
	var controls []map[string]any
	for _, sample := range samples {
		mapping, err := buildSINFAssociations(syntheticLicenseFiles(t, sample.entries))
		entries := make(map[string][]int)
		for name, data := range sample.entries {
			values := make([]int, len(data))
			for i, b := range data {
				values[i] = int(b)
			}
			entries[name] = values
		}
		controls = append(controls, map[string]any{"name": sample.name, "entries": entries, "accepted": err == nil, "mappings": mapping})
	}
	// Sort public cases as the deliberately unordered source map is not evidence.
	sortPublic := func(i, j int) bool { return controls[i]["name"].(string) < controls[j]["name"].(string) }
	sort.Slice(controls, sortPublic)
	data, err := json.MarshalIndent(controls, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "fairplay-license-associations-public-vectors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
}
