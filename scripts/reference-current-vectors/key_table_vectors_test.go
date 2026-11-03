// Public synthetic key-table controls for UnfairPlay b3a7a432 (MIT).
// Private signing keys are generated in memory and never exported.
package fairplay

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func keyTablePublicBytes(data []byte) []int {
	values := make([]int, len(data))
	for i, value := range data {
		values[i] = int(value)
	}
	return values
}

func TestRustKeyTablePublicVectors(t *testing.T) {
	dir := os.Getenv("IPATOOL_PUBLIC_VECTOR_DIR")
	if dir == "" {
		t.Skip("set IPATOOL_PUBLIC_VECTOR_DIR for public fixture export")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("output directory must be absolute")
	}
	signer := newSyntheticSUPPSigner(t)
	const member = "Payload/A.app/A"
	const base = "Payload/A.app/SC_Info/A"
	const page = 4096
	signatures := [][]byte{[]byte("first complete signature"), []byte("second complete signature")}
	thin := []machoSlice{{offset: 0, size: 4 * page, layout: machoLayout{cpuType: 0x0100000c, cpuSubtype: 2, cryptOffset: page, cryptSize: page, cryptID: 1, signatureOffset: 3 * page, signatureSize: uint32(len(signatures[0]))}}}
	fat := []machoSlice{
		{offset: page, size: 3 * page, layout: machoLayout{cpuType: 0x0100000c, cpuSubtype: 2, cryptOffset: page, cryptSize: page, cryptID: 1, signatureOffset: 2 * page, signatureSize: uint32(len(signatures[0]))}},
		{offset: 5 * page, size: 3 * page, layout: machoLayout{cpuType: 0x0c, cpuSubtype: 9, cryptOffset: page, cryptSize: page, cryptID: 1, signatureOffset: 2 * page, signatureSize: uint32(len(signatures[1]))}},
	}
	records := func(count int) [][32]byte {
		result := make([][32]byte, count)
		for i := range result {
			for j := range result[i] {
				result[i][j] = byte(13*i + j + 1)
			}
		}
		return result
	}
	f := func(variant byte, architectures []supfArchitecture) []byte {
		payload := binary.BigEndian.AppendUint32(nil, uint32(len(architectures)))
		for _, arch := range architectures {
			entry := binary.BigEndian.AppendUint32(nil, arch.cpuType)
			entry = binary.BigEndian.AppendUint32(entry, arch.cpuSubtype)
			if variant == 3 {
				entry = append(entry, arch.SignatureSHA1[:]...)
			}
			entry = binary.BigEndian.AppendUint32(entry, uint32(len(arch.records)))
			for _, record := range arch.records {
				entry = append(entry, record[:]...)
			}
			payload = binary.BigEndian.AppendUint32(payload, uint32(len(entry)))
			payload = append(payload, entry...)
		}
		result := []byte{variant, 0, 0, 0}
		result = binary.BigEndian.AppendUint32(result, uint32(len(payload)))
		return append(result, payload...)
	}
	arch := supfArchitecture{cpuType: 0x0100000c, cpuSubtype: 2, records: records(1), SignatureSHA1: sha1.Sum(signatures[0]), HasSignatureSHA1: true}
	f3, f5 := f(3, []supfArchitecture{arch}), f(5, []supfArchitecture{arch})
	p1 := signer.encode(t, 1, sha1.Sum(signatures[0]), records(2))
	p4 := signer.encode(t, 4, [20]byte{}, records(2))
	type sample struct {
		name             string
		files            map[string][]byte
		slices           []machoSlice
		changedSignature bool
	}
	var samples []sample
	add := func(name string, files map[string][]byte) {
		samples = append(samples, sample{name: name, files: files, slices: thin})
	}
	add("v5 only", map[string][]byte{base + ".v5.supf": f5})
	add("v3 only", map[string][]byte{base + ".supf": f3})
	add("consistent f pair", map[string][]byte{base + ".supf": f3, base + ".v5.supf": f5})
	add("empty legacy f with v5", map[string][]byte{base + ".supf": {}, base + ".v5.supf": f5})
	add("empty legacy f alone", map[string][]byte{base + ".supf": {}})
	add("empty v5 with legacy", map[string][]byte{base + ".supf": f3, base + ".v5.supf": {}})
	add("malformed legacy never retries v5", map[string][]byte{base + ".supf": {3}, base + ".v5.supf": f5})
	add("malformed v5 never retries legacy", map[string][]byte{base + ".supf": f3, base + ".v5.supf": {5}})
	add("v5 under legacy suffix", map[string][]byte{base + ".supf": f5})
	add("v3 under v5 suffix", map[string][]byte{base + ".v5.supf": f3})
	other := arch
	other.records = records(2)
	add("f pair different page counts", map[string][]byte{base + ".supf": f3, base + ".v5.supf": f(5, []supfArchitecture{other})})
	other = arch
	other.records = records(1)
	other.records[0][0] ^= 1
	add("f pair different records", map[string][]byte{base + ".supf": f3, base + ".v5.supf": f(5, []supfArchitecture{other})})
	other = arch
	other.cpuSubtype = 0
	add("f pair different architecture", map[string][]byte{base + ".supf": f3, base + ".v5.supf": f(5, []supfArchitecture{other})})
	add("f class precedes malformed p", map[string][]byte{base + ".v5.supf": f5, base + ".supp": {1}})
	add("malformed f never retries valid p", map[string][]byte{base + ".supf": {3}, base + ".supp": p1})
	add("v1 p only", map[string][]byte{base + ".supp": p1})
	add("v4 p only", map[string][]byte{base + ".v4.supp": p4})
	add("consistent p pair", map[string][]byte{base + ".supp": p1, base + ".v4.supp": p4})
	add("p pair different counts", map[string][]byte{base + ".supp": p1, base + ".v4.supp": signer.encode(t, 4, [20]byte{}, records(3))})
	pRecords := records(2)
	pRecords[1][1] ^= 1
	add("p pair different records", map[string][]byte{base + ".supp": p1, base + ".v4.supp": signer.encode(t, 4, [20]byte{}, pRecords)})
	add("v4 under legacy p suffix", map[string][]byte{base + ".supp": p4})
	add("v1 under v4 suffix", map[string][]byte{base + ".v4.supp": p1})
	add("empty p never retries v4", map[string][]byte{base + ".supp": {}, base + ".v4.supp": p4})
	tampered := append([]byte(nil), p4...)
	tampered[len(tampered)-1] ^= 1
	add("unauthenticated p", map[string][]byte{base + ".v4.supp": tampered})
	add("p too few records", map[string][]byte{base + ".v4.supp": signer.encode(t, 4, [20]byte{}, records(1))})
	add("p too many records", map[string][]byte{base + ".v4.supp": signer.encode(t, 4, [20]byte{}, records(3))})
	add("missing key table", map[string][]byte{})
	for _, name := range []string{"v3 wrong signature", "f pair preserves signature", "v1 wrong signature", "p pair preserves signature"} {
		files := map[string][]byte{base + ".supf": f3}
		if name == "f pair preserves signature" {
			files[base+".v5.supf"] = f5
		}
		if name == "v1 wrong signature" || name == "p pair preserves signature" {
			files = map[string][]byte{base + ".supp": p1}
			if name == "p pair preserves signature" {
				files[base+".v4.supp"] = p4
			}
		}
		samples = append(samples, sample{name: name, files: files, slices: thin, changedSignature: true})
	}
	for _, name := range []string{"p unaligned start", "p unaligned size", "p duplicate architecture"} {
		slices := append([]machoSlice(nil), thin...)
		if name == "p unaligned start" {
			slices[0].layout.cryptOffset++
		}
		if name == "p unaligned size" {
			slices[0].layout.cryptSize--
		}
		if name == "p duplicate architecture" {
			slices = append(slices, slices[0])
		}
		samples = append(samples, sample{name: name, files: map[string][]byte{base + ".v4.supp": p4}, slices: slices})
	}
	joined := append(append([]byte(nil), signatures[0]...), signatures[1]...)
	fatP1 := signer.encode(t, 1, sha1.Sum(joined), records(7))
	fatP4 := signer.encode(t, 4, [20]byte{}, records(7))
	for _, name := range []string{"universal p v1", "universal p v4", "universal p pair", "universal p wrong signature"} {
		files := map[string][]byte{base + ".supp": fatP1}
		if name == "universal p v4" {
			files = map[string][]byte{base + ".v4.supp": fatP4}
		}
		if name == "universal p pair" {
			files[base+".v4.supp"] = fatP4
		}
		samples = append(samples, sample{name: name, files: files, slices: fat, changedSignature: name == "universal p wrong signature"})
	}
	other = arch
	other.cpuType = 0x0c
	other.cpuSubtype = 9
	other.SignatureSHA1 = sha1.Sum(signatures[1])
	samples = append(samples, sample{name: "f pair architecture order differs", files: map[string][]byte{base + ".supf": f(3, []supfArchitecture{arch, other}), base + ".v5.supf": f(5, []supfArchitecture{other, arch})}, slices: fat})
	var controls []map[string]any
	for _, sample := range samples {
		selected, table, err := selectImageKeyTableWithCA(syntheticLicenseFiles(t, sample.files), member, sample.slices, &signer.authority.PublicKey)
		files := map[string][]int{}
		for name, data := range sample.files {
			files[name] = keyTablePublicBytes(data)
		}
		var layouts []map[string]any
		var chunks []map[string]any
		var total uint64
		for index, slice := range sample.slices {
			l := slice.layout
			layouts = append(layouts, map[string]any{"offset": slice.offset, "size": slice.size, "cpu_type": l.cpuType, "cpu_subtype": l.cpuSubtype, "crypt_offset": l.cryptOffset, "crypt_size": l.cryptSize, "crypt_id": l.cryptID, "signature_offset": l.signatureOffset, "signature_size": l.signatureSize})
			if slice.offset+slice.size > total {
				total = slice.offset + slice.size
			}
			chunks = append(chunks, map[string]any{"offset": slice.offset + uint64(l.signatureOffset), "bytes": keyTablePublicBytes(signatures[index%len(signatures)])})
		}
		control := map[string]any{"name": sample.name, "files": files, "slices": layouts, "signature_chunks": chunks, "source_bytes": total, "changed_signature": sample.changedSignature, "accepted": err == nil}
		if err == nil {
			control["member"], control["variant"] = selected, table.variant
			var arches []map[string]any
			for _, a := range table.architectures {
				h := sha256.New()
				for _, r := range a.records {
					h.Write(r[:])
				}
				value := map[string]any{"cpu_type": a.cpuType, "cpu_subtype": a.cpuSubtype, "records_sha256": hex.EncodeToString(h.Sum(nil)), "pages": len(a.records)}
				if a.HasSignatureSHA1 {
					value["signature_sha1"] = hex.EncodeToString(a.SignatureSHA1[:])
				}
				arches = append(arches, value)
			}
			control["architectures"] = arches
			if table.HasUniversalSignatureSHA1 {
				control["universal_signature_sha1"] = hex.EncodeToString(table.UniversalSignatureSHA1[:])
			}
			source := make([]byte, total)
			for index, slice := range sample.slices {
				copy(source[slice.offset+uint64(slice.layout.signatureOffset):], signatures[index%len(signatures)])
			}
			if sample.changedSignature {
				source[sample.slices[0].offset+uint64(sample.slices[0].layout.signatureOffset)] ^= 1
			}
			bindingErr := table.ValidateUniversalSignatureBinding(source, sample.slices)
			for _, slice := range sample.slices {
				if bindingErr == nil && slice.layout.cryptID != 0 {
					bindingErr = table.ValidateSignatureBinding(source[slice.offset:slice.offset+slice.size], slice.layout)
				}
			}
			control["binding_accepted"] = bindingErr == nil
		}
		controls = append(controls, control)
	}
	output := map[string]any{"authority_modulus": keyTablePublicBytes(signer.authority.N.Bytes()), "authority_exponent": []int{1, 0, 1}, "controls": controls}
	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "fairplay-key-table-public-vectors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err = file.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
}
