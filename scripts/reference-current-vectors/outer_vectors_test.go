// Test-only public vector export for UnfairPlay b3a7a432. No private inputs.
package recovery

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func rustOuterDigest(table [outerTableWords]uint32, state outerTableRoundState, control outerIterationControl) string {
	var b []byte
	word := func(w uint32) { var x [4]byte; binary.LittleEndian.PutUint32(x[:], w); b = append(b, x[:]...) }
	for _, w := range table {
		word(w)
	}
	for _, w := range state.Words {
		word(w)
	}
	b = append(b, state.Hardware[:]...)
	b = append(b, state.HardwareIndex)
	b = append(b, state.Codec[:]...)
	b = append(b, state.Source[:]...)
	b = append(b, state.Tail[:]...)
	b = append(b, state.Writer[:]...)
	word(state.OptionalWord)
	word(control.X1)
	word(control.CounterSeed)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func TestRustOuterPublicVectors(t *testing.T) {
	if os.Getenv("IPATOOL_PUBLIC_VECTOR_DIR") == "" {
		t.Skip("set IPATOOL_PUBLIC_VECTOR_DIR for public fixture export")
	}
	type Case struct {
		Index  int    `json:"index"`
		Next   uint32 `json:"next"`
		SHA256 string `json:"sha256"`
	}
	var cases []Case
	for n := 0; n < 32; n++ {
		var table [outerTableWords]uint32
		var state outerTableRoundState
		for i := range table {
			table[i] = uint32(i+1)*0x9e3779b9 ^ uint32(n)*0x1234567
		}
		for i := range state.Words {
			state.Words[i] = uint32(i+1)*0x31415927 ^ uint32(n)*0x1b2b3b4b
		}
		for i := range state.Hardware {
			state.Hardware[i] = byte(n*17 + i*37)
		}
		state.HardwareIndex = byte(n % 6)
		for i := range state.Codec {
			state.Codec[i] = byte(i*29 + n*13)
		}
		for i := range state.Source {
			state.Source[i] = byte(i*31 + n*19)
		}
		for i := range state.Tail {
			state.Tail[i] = byte(i*41 + n*3)
		}
		for i := range state.Writer {
			state.Writer[i] = byte(i*43 + n*5)
		}
		control := outerIterationControl{X1: []uint32{0x60319d83, 0x60319e4b, 0x60319d87}[n%3], CounterSeed: uint32(n)*0xf1234567 + 0x0a782fec}
		next, ok := applyOuterFullIteration(&table, uint32(n*13%167), &state, &control)
		if !ok {
			t.Fatal("synthetic full iteration failed", n)
		}
		cases = append(cases, Case{n, next, rustOuterDigest(table, state, control)})
	}
	data, hw, _ := syntheticNativeSIDB(t, 64)
	source, layout, _, err := deriveNativeSelectionSource(data, hw)
	if err != nil {
		t.Fatal(err)
	}
	var bytes, hardware []int
	for _, b := range data {
		bytes = append(bytes, int(b))
	}
	for _, b := range hw {
		hardware = append(hardware, int(b))
	}
	hash := sha256.Sum256(source)
	value := map[string]any{"iterations": cases, "container": bytes, "hardware": hardware, "source_sha256": hex.EncodeToString(hash[:]), "layout": map[string]int{
		"codec_bytes": layout.CodecBytes, "payload_offset": layout.PayloadOffset, "payload_bytes": layout.PayloadBytes, "source_bytes": layout.SourceBytes,
		"selector_modulus": layout.SelectorModulus, "selected_slot": layout.SelectedSlot, "root_cursor": layout.RootCursor, "iterations": layout.OuterIterations}}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writePublicVectors(t, "fairplay-current-outer-public-vectors.json", encoded)
}

func writePublicVectors(t *testing.T, name string, data []byte) {
	t.Helper()
	root := os.Getenv("IPATOOL_PUBLIC_VECTOR_DIR")
	if !filepath.IsAbs(root) {
		t.Fatal("IPATOOL_PUBLIC_VECTOR_DIR must be an absolute existing directory")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Fatal("vector destination must exist")
	}
	file, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write(data); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
}
