// Test-only public vector export for UnfairPlay b3a7a432. No private inputs.
package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func rustInts(b []byte) []int {
	r := make([]int, len(b))
	for i, v := range b {
		r[i] = int(v)
	}
	return r
}
func TestRustRecoveryPublicVectors(t *testing.T) {
	if os.Getenv("IPATOOL_PUBLIC_VECTOR_DIR") == "" {
		t.Skip("set IPATOOL_PUBLIC_VECTOR_DIR for public fixture export")
	}
	var controls []map[string]any
	for n := 0; n < 2; n++ {
		data, hw, layout := syntheticNativeSIDBMatching(t, selectionSIDBPayloadBytes, func(l currentSIDBLayout) bool { return n == 0 || l.SelectedSlot >= 14 })
		source, _, _, err := deriveNativeSelectionSource(data, hw)
		if err != nil {
			t.Fatal(err)
		}
		key, err := deriveSelectedEnrollmentKey(source[32:], layout.SelectedSlot)
		if err != nil {
			t.Fatal(err)
		}
		plain, registry, sinf, user, keyID, _ := syntheticProductionRoute(t, hw, selectionSIDBPayloadBytes)
		fillSyntheticSelectionSIDBContainer(t, data, layout.PayloadOffset, plain, key)
		sealSyntheticSelectionContainer(t, data, source)
		registries, stateHash, _, actualLayout, err := deriveCurrentSelectionRegistryCandidatesWithEvidence(map[string][]byte{"SC Info.sidb": data}, hw)
		if err != nil {
			t.Fatal(err)
		}
		pack, route, err := currentEnrollmentPackWithContextEvidence(context.Background(), map[string][]byte{"App.sinf": sinf}, registries, hw, nil)
		if err != nil {
			t.Fatal(err)
		}
		modelHash := sha256.Sum256(pack)
		bodyHash := sha256.Sum256(plain)
		class, err := accountClassKey(hw, user, keyID)
		if err != nil {
			t.Fatal(err)
		}
		metadata := -1
		for i, r := range registry.Records {
			if r.SourceOffset == layout.RootCursor+40 {
				metadata = i
			}
		}
		if metadata < 0 {
			t.Fatal("missing synthetic metadata")
		}
		precursor, err := deriveCurrentSINFPrecursorFromRecordWindow(registry.Records[metadata], 0, class)
		if err != nil {
			t.Fatal(err)
		}
		trap := syntheticCurrentSINFForPrecursorRights(t, precursor, 104)
		start, end, err := enrollmentAtom(trap, 0, len(trap), "sinf")
		if err != nil {
			t.Fatal(err)
		}
		start, end, err = enrollmentAtom(trap, start, end, "schi")
		if err != nil {
			t.Fatal(err)
		}
		u, _, err := enrollmentAtom(trap, start, end, "user")
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint32(trap[u:], user)
		k, _, err := enrollmentAtom(trap, start, end, "key ")
		if err != nil {
			t.Fatal(err)
		}
		binary.BigEndian.PutUint32(trap[k:], keyID)
		if _, err := currentEnrollmentPackWithContext(context.Background(), map[string][]byte{"App.sinf": trap}, registries, hw, nil); err == nil {
			t.Fatal("metadata fallback accepted")
		}

		controls = append(controls, map[string]any{"container": rustInts(data), "hardware": rustInts(hw), "sinf": rustInts(sinf), "trap_sinf": rustInts(trap), "model_sha256": hex.EncodeToString(modelHash[:]), "body_sha256": hex.EncodeToString(bodyHash[:]), "state_sha256": stateHash, "slot": layout.SelectedSlot, "source_bytes": layout.SourceBytes, "route": route, "layout": actualLayout})
	}
	var classes []map[string]any
	for n := 0; n < 32; n++ {
		hw := make([]byte, 6)
		for i := range hw {
			hw[i] = byte(n*17 + i*37)
		}
		user, keyID := uint32(n)*0x12345678, uint32(n)*0x87654321+1
		key, err := accountClassKey(hw, user, keyID)
		if err != nil {
			t.Fatal(err)
		}
		classes = append(classes, map[string]any{"hardware": rustInts(hw), "user": user, "key": keyID, "class_key": rustInts(key[:])})
	}
	bytes, err := json.MarshalIndent(map[string]any{"controls": controls, "classes": classes}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writePublicVectors(t, "fairplay-current-recovery-public-vectors.json", bytes)
}
