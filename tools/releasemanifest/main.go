package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type PlatformAsset struct {
	Checksum string `json:"checksum"`
	URL      string `json:"url"`
}

type AgentManifest struct {
	Version              string                   `json:"version"`
	MinAgentVersion      string                   `json:"min_agent_version"`
	PrivacyPolicyVersion string                   `json:"privacy_policy_version"`
	PrivacyPolicyURL     string                   `json:"privacy_policy_url"`
	ReleaseNotes         string                   `json:"release_notes"`
	RequiresConsent      bool                     `json:"requires_consent"`
	Platforms            map[string]PlatformAsset `json:"platforms"`
	KeyID                string                   `json:"key_id,omitempty"`
	Signature            string                   `json:"signature,omitempty"`
}

var platforms = []struct {
	os       string
	arch     string
	filename string
}{
	{"linux", "amd64", "uptriva-agent"},
	{"linux", "arm64", "uptriva-agent"},
	{"windows", "amd64", "uptriva-agent.exe"},
	{"darwin", "amd64", "uptriva-agent"},
	{"darwin", "arm64", "uptriva-agent"},
}

func computeSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func compareVersions(a, b string) int {
	a = strings.TrimPrefix(strings.TrimSpace(a), "v")
	b = strings.TrimPrefix(strings.TrimSpace(b), "v")
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			fmt.Sscanf(aParts[i], "%d", &aNum)
		}
		if i < len(bParts) {
			fmt.Sscanf(bParts[i], "%d", &bNum)
		}
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}

func assetName(osName, arch, filename string) string {
	ext := ""
	if strings.HasSuffix(filename, ".exe") {
		ext = ".exe"
	}
	return fmt.Sprintf("uptriva-agent-%s-%s%s", osName, arch, ext)
}

func manifestSigningPayload(m *AgentManifest) []byte {
	signed := *m
	signed.KeyID = ""
	signed.Signature = ""
	payload, _ := json.Marshal(signed)
	return payload
}

func loadSigningKey() ed25519.PrivateKey {
	raw, err := hex.DecodeString(strings.TrimSpace(os.Getenv("AGENT_RELEASE_SIGNING_KEY")))
	if err != nil {
		log.Fatal("AGENT_RELEASE_SIGNING_KEY is not valid hex")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw)
	default:
		log.Fatal("AGENT_RELEASE_SIGNING_KEY must be a 32-byte seed or 64-byte private key")
		return nil
	}
}

func main() {
	dir := flag.String("dir", "", "release staging directory (required)")
	tag := flag.String("tag", "", "git tag of the release, e.g. v1.7.0 (required)")
	repo := flag.String("repo", "Uptriva/uptriva-agent", "GitHub repo in owner/name form")
	out := flag.String("out", "", "output path for manifest.json (required)")
	flag.Parse()

	if *dir == "" || *tag == "" || *out == "" {
		log.Fatal("usage: releasemanifest -dir DIR -tag TAG -out PATH [-repo owner/name]")
	}

	versionBytes, err := os.ReadFile(filepath.Join(*dir, "version"))
	if err != nil {
		log.Fatalf("version file not found in %s: %v", *dir, err)
	}
	version := strings.TrimSpace(string(versionBytes))

	minVersion := ""
	if data, err := os.ReadFile(filepath.Join(*dir, "min_agent_version")); err == nil {
		minVersion = strings.TrimSpace(string(data))
	}
	if minVersion != "" && compareVersions(minVersion, version) >= 0 {
		log.Printf("ignoring min_agent_version=%s for release %s", minVersion, version)
		minVersion = ""
	}

	ppVersion := "1.0.0"
	if data, err := os.ReadFile(filepath.Join(*dir, "privacy_policy_version")); err == nil {
		ppVersion = strings.TrimSpace(string(data))
	}

	ppURL := os.Getenv("PRIVACY_POLICY_URL")
	if ppURL == "" {
		ppURL = "https://uptriva.com/privacy"
	}

	releaseNotes := ""
	if data, err := os.ReadFile(filepath.Join(*dir, "release_notes.md")); err == nil {
		releaseNotes = string(data)
	}

	requiresConsent := false
	if _, err := os.Stat(filepath.Join(*dir, "requires_consent")); err == nil {
		requiresConsent = true
	}

	platformMap := map[string]PlatformAsset{}
	for _, p := range platforms {
		binPath := filepath.Join(*dir, p.os, p.arch, p.filename)
		checksum, err := computeSHA256(binPath)
		if err != nil {
			log.Fatalf("missing or unreadable binary %s: %v", binPath, err)
		}
		name := assetName(p.os, p.arch, p.filename)
		platformMap[p.os+"/"+p.arch] = PlatformAsset{
			Checksum: checksum,
			URL:      fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", *repo, *tag, name),
		}
	}

	manifest := AgentManifest{
		Version:              version,
		MinAgentVersion:      minVersion,
		PrivacyPolicyVersion: ppVersion,
		PrivacyPolicyURL:     ppURL,
		ReleaseNotes:         releaseNotes,
		RequiresConsent:      requiresConsent,
		Platforms:            platformMap,
	}

	keyHex := strings.TrimSpace(os.Getenv("AGENT_RELEASE_SIGNING_KEY"))
	if keyHex == "" {
		log.Println("WARN: AGENT_RELEASE_SIGNING_KEY not set, emitting unsigned manifest")
	} else {
		key := loadSigningKey()
		pub := key.Public().(ed25519.PublicKey)
		manifest.KeyID = hex.EncodeToString(pub[:8])
		manifest.Signature = hex.EncodeToString(ed25519.Sign(key, manifestSigningPayload(&manifest)))
	}

	manifestJSON, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, manifestJSON, 0644); err != nil {
		log.Fatal(err)
	}
	log.Printf("manifest written to %s (version=%s, signed=%v, platforms=%d)", *out, version, manifest.Signature != "", len(platformMap))
}
