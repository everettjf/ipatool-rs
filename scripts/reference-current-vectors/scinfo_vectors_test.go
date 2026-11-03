// Test-only public signature corpus for UnfairPlay b3a7a432 (MIT).
// Keys are generated in memory and discarded. Only public values are exported.
// Unlike the algorithm vectors, a regenerated PKI corpus has different bytes.
package scinfo

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func publicInts(b []byte) []int {
	r := make([]int, len(b))
	for i, v := range b {
		r[i] = int(v)
	}
	return r
}

func TestRustSCInfoPublicVectors(t *testing.T) {
	dir := os.Getenv("IPATOOL_PUBLIC_VECTOR_DIR")
	if dir == "" {
		t.Skip("set IPATOOL_PUBLIC_VECTOR_DIR for public fixture export")
	}
	if !filepath.IsAbs(dir) {
		t.Fatal("output directory must be absolute")
	}
	ca, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	issuer := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Apple FairPlay Certification Authority", Organization: []string{"Apple Inc."}, OrganizationalUnit: []string{"Apple Certification Authority"}}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	var controls []map[string]any
	for _, variant := range []byte{1, 3, 4, 5} {
		for _, invalid := range []string{"", "subject", "ca", "issuer"} {
			subject := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "AP.synthetic", Organization: []string{"Apple Inc."}, OrganizationalUnit: []string{"Apple FairPlay"}}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(3, 0), SignatureAlgorithm: x509.SHA1WithRSA}
			parent := *issuer
			switch invalid {
			case "subject":
				subject.Subject.CommonName = "other.synthetic"
			case "ca":
				subject.IsCA = true
				subject.BasicConstraintsValid = true
			case "issuer":
				parent.Subject.CommonName = "Other Authority"
			}
			cert, err := x509.CreateCertificate(rand.Reader, subject, &parent, &leaf.PublicKey, ca)
			if err != nil {
				t.Fatal(err)
			}
			prefix := []byte{variant, 0, 0, 0}
			put := func(v uint32) { prefix = binary.BigEndian.AppendUint32(prefix, v) }
			if variant == 3 || variant == 5 {
				entryBytes := uint32(12 + 64)
				if variant == 3 {
					entryBytes += 20
				}
				put(4 + 4 + entryBytes)
				put(1)
				put(entryBytes)
				put(0x0100000c)
				put(2)
				if variant == 3 {
					prefix = append(prefix, make([]byte, 20)...)
				}
			} else if variant == 1 {
				prefix = append(prefix, make([]byte, 20)...)
			}
			put(2)
			for i := 1; i <= 32; i++ {
				prefix = append(prefix, byte(i))
			}
			for i := 0; i < 32; i++ {
				prefix = append(prefix, 0x47)
			}
			var hash crypto.Hash
			var digest []byte
			if variant == 1 || variant == 3 {
				v := sha1.Sum(prefix)
				hash, digest = crypto.SHA1, v[:]
			} else {
				v := sha256.Sum256(prefix)
				hash, digest = crypto.SHA256, v[:]
			}
			sig, err := rsa.SignPKCS1v15(rand.Reader, leaf, hash, digest)
			if err != nil {
				t.Fatal(err)
			}
			accepted := VerifyEnvelope(variant, prefix, cert, sig, &ca.PublicKey) == nil
			if accepted != (invalid == "") {
				t.Fatal("unexpected Go signature result")
			}
			blob := append([]byte(nil), prefix...)
			blob = binary.BigEndian.AppendUint32(blob, uint32(len(cert)))
			blob = append(blob, cert...)
			if variant == 3 || variant == 5 {
				blob = binary.BigEndian.AppendUint32(blob, uint32(len(sig)))
			}
			blob = append(blob, sig...)
			controls = append(controls, map[string]any{"variant": variant, "invalid": invalid, "accepted": accepted, "keyfile": publicInts(blob)})
		}
	}
	data, err := json.MarshalIndent(map[string]any{"authority_modulus": publicInts(ca.N.Bytes()), "authority_exponent": publicInts([]byte{1, 0, 1}), "controls": controls}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "fairplay-scinfo-public-vectors.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
}
