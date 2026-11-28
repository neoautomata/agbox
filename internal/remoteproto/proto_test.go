package remoteproto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFrameRoundTripAndCap(t *testing.T) {
	var buf bytes.Buffer
	rawSent, err := WriteFrame(&buf, FrameHello, HelloPayload{
		ProtoVer: ProtocolVersion,
		Role:     "remote",
		User:     "ops",
		UID:      1000,
	}, PreAuthMaxFrameBytes)
	if err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}
	typ, payload, rawRecv, err := ReadFrame(&buf, PreAuthMaxFrameBytes)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if typ != FrameHello {
		t.Fatalf("frame type = %q, want %q", typ, FrameHello)
	}
	if !bytes.Equal(rawSent, rawRecv) {
		t.Fatal("raw frame bytes differ between write and read")
	}
	var got HelloPayload
	if err := DecodeStrict(payload, &got); err != nil {
		t.Fatalf("DecodeStrict failed: %v", err)
	}
	if got.User != "ops" || got.UID != 1000 {
		t.Fatalf("unexpected decoded payload: %+v", got)
	}

	// Reject oversized frame BEFORE allocation.
	var hugeHdr [4]byte
	binary.BigEndian.PutUint32(hugeHdr[:], PreAuthMaxFrameBytes+1)
	if _, _, _, err := ReadFrame(bytes.NewReader(hugeHdr[:]), PreAuthMaxFrameBytes); err == nil {
		t.Fatal("expected error for oversized pre-auth frame")
	}

	// Reject zero-length frame.
	var zeroHdr [4]byte
	if _, _, _, err := ReadFrame(bytes.NewReader(zeroHdr[:]), PreAuthMaxFrameBytes); err == nil {
		t.Fatal("expected error for zero-length frame")
	}

	// Reject trailing JSON tokens inside one frame.
	trailing := []byte(`{"type":"ping"}{"extra":1}`)
	var trBuf bytes.Buffer
	var trHdr [4]byte
	binary.BigEndian.PutUint32(trHdr[:], uint32(len(trailing)))
	trBuf.Write(trHdr[:])
	trBuf.Write(trailing)
	if _, _, _, err := ReadFrame(&trBuf, PreAuthMaxFrameBytes); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing JSON rejection, got %v", err)
	}

	// Reject unknown envelope field.
	unknownField := []byte(`{"type":"ping","extra":true}`)
	var ufBuf bytes.Buffer
	binary.BigEndian.PutUint32(trHdr[:], uint32(len(unknownField)))
	ufBuf.Write(trHdr[:])
	ufBuf.Write(unknownField)
	if _, _, _, err := ReadFrame(&ufBuf, PreAuthMaxFrameBytes); err == nil {
		t.Fatal("expected unknown envelope field rejection")
	}

	// Reject missing type.
	missingType := []byte(`{"payload":{}}`)
	var mtBuf bytes.Buffer
	binary.BigEndian.PutUint32(trHdr[:], uint32(len(missingType)))
	mtBuf.Write(trHdr[:])
	mtBuf.Write(missingType)
	if _, _, _, err := ReadFrame(&mtBuf, PreAuthMaxFrameBytes); err == nil {
		t.Fatal("expected missing frame type rejection")
	}
}

func TestDurationAndByteSizeParsers(t *testing.T) {
	durCases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"60", 60 * time.Second, false},
		{"30s", 30 * time.Second, false},
		{"2m", 2 * time.Minute, false},
		{"0", 0, true},
		{"-5", 0, true},
		{"-10s", 0, true},
		{"9999999999999999999", 0, true},
		{"9223372037", 0, true},
		{"9223372036", 9223372036 * time.Second, false},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tc := range durCases {
		got, err := ParseDurationOrSeconds(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseDurationOrSeconds(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseDurationOrSeconds(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}

	sizeCases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"1024", 1024, false},
		{"256K", 256 * 1024, false},
		{"256KiB", 256 * 1024, false},
		{"2M", 2 * 1024 * 1024, false},
		{"2MiB", 2 * 1024 * 1024, false},
		{"0", 0, true},
		{"-1K", 0, true},
		{"bad", 0, true},
	}
	for _, tc := range sizeCases {
		got, err := ParseByteSize(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("ParseByteSize(%q) err=%v, wantErr=%v", tc.in, err, tc.wantErr)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("ParseByteSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestVaudenayTLS13CommitRevealAndPinning(t *testing.T) {
	srvID, err := GenerateEphemeralIdentity("remote")
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := GenerateEphemeralIdentity("host")
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := GenerateEphemeralIdentity("attacker")
	if err != nil {
		t.Fatal(err)
	}

	// Reject non-Ed25519 certificate (ECDSA).
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ec"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ec"},
	}, &ecKey.PublicKey, ecKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPeerEd25519Cert([][]byte{ecDER}, nil); err == nil {
		t.Fatal("expected VerifyPeerEd25519Cert to reject ECDSA cert")
	}

	// Complete TLS 1.3 handshake over net.Pipe and verify identical EKM + SAS.
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	srvTLS := tls.Server(c1, ServerTLSConfig(srvID, nil))
	cliTLS := tls.Client(c2, ClientTLSConfig(cliID, nil))

	errCh := make(chan error, 1)
	go func() {
		errCh <- srvTLS.Handshake()
	}()
	if err := cliTLS.Handshake(); err != nil {
		t.Fatalf("client TLS handshake failed: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("server TLS handshake failed: %v", err)
	}

	ekmC, err := ExportPairingEKM(cliTLS)
	if err != nil {
		t.Fatal(err)
	}
	ekmS, err := ExportPairingEKM(srvTLS)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ekmC, ekmS) {
		t.Fatal("exported EKM mismatch across TLS 1.3 peers")
	}

	rawHelloR := []byte(`{"type":"hello","payload":{"role":"remote"}}`)
	rawHelloH := []byte(`{"type":"hello","payload":{"role":"host"}}`)
	trC := ComputeTranscript(ekmC, cliID.DER, srvID.DER, rawHelloR, rawHelloH)
	trS := ComputeTranscript(ekmS, cliID.DER, srvID.DER, rawHelloR, rawHelloH)
	if trC != trS {
		t.Fatal("transcript mismatch")
	}

	// Changing one byte in rawHelloR changes the transcript (length-prefixed tamper check).
	tampered := ComputeTranscript(ekmC, cliID.DER, srvID.DER, append(rawHelloR, ' '), rawHelloH)
	if tampered == trC {
		t.Fatal("tampered hello produced identical transcript")
	}

	nH, _ := RandomBytes32()
	nR, _ := RandomBytes32()
	commit := ComputeCommit(nH, trC)
	if commit != ComputeCommit(nH, trS) {
		t.Fatal("commit mismatch")
	}
	sasC, sidC := DeriveSASAndSession(trC, nH, nR)
	sasS, sidS := DeriveSASAndSession(trS, nH, nR)
	if sasC != sasS || sidC != sidS {
		t.Fatalf("SAS/session mismatch: %s vs %s", sasC, sasS)
	}
	if len(sasC) != 14 || sasC[4] != '-' || sasC[9] != '-' {
		t.Fatalf("unexpected SAS format %q (want XXXX-XXXX-XXXX)", sasC)
	}

	// MITM grinding a different nonce or cert fails commit verification.
	otherN, _ := RandomBytes32()
	if ComputeCommit(otherN, trC) == commit {
		t.Fatal("different nonce matched commitment")
	}

	// Pinning rejects otherID.
	if _, _, err := VerifyPeerEd25519Cert([][]byte{otherID.DER}, &cliID.Fingerprint); err == nil {
		t.Fatal("expected pinned cert check to reject mismatched identity")
	}
}

func TestSanitizerAndJSONControlEscaping(t *testing.T) {
	// C0 ANSI CSI, CR overwrite, DEL, C1 CSI (U+009B), C1 OSC (U+009D), BiDi RLO (U+202E), invalid UTF-8.
	dirty := "ls\x1b[2J\rrm -rf /\x7f\u009b31m\u009d52;c;\u202esafe\xff"
	clean := SanitizeLine(dirty)
	for i := 0; i < len(clean); i++ {
		if clean[i] < 0x20 || clean[i] > 0x7E {
			t.Fatalf("SanitizeLine emitted non-printable byte 0x%02x in %q", clean[i], clean)
		}
	}
	if !strings.Contains(clean, `\x1b`) || !strings.Contains(clean, `\r`) || !strings.Contains(clean, `\u009b`) || !strings.Contains(clean, `\u202e`) {
		t.Fatalf("SanitizeLine did not visibly escape spoofing controls: %q", clean)
	}

	// EscapeJSONControls escapes DEL, C1, and BiDi runes in editor JSON buffers.
	rawJSON := []byte("{\"arg\":\"a\x7f\u009b\u202eb\"}")
	escaped := string(EscapeJSONControls(rawJSON))
	if strings.ContainsRune(escaped, '\x7f') || strings.ContainsRune(escaped, '\u009b') || strings.ContainsRune(escaped, '\u202e') {
		t.Fatalf("EscapeJSONControls left raw control runes: %q", escaped)
	}
	if !strings.Contains(escaped, `\u007f`) || !strings.Contains(escaped, `\u009b`) || !strings.Contains(escaped, `\u202e`) {
		t.Fatalf("EscapeJSONControls missing expected \\uXXXX escapes: %q", escaped)
	}

	if !IsBinary([]byte("abc\x00def")) {
		t.Error("expected NUL bytes to be detected as binary")
	}
	if !IsBinary([]byte{0xff, 0xfe}) {
		t.Error("expected invalid UTF-8 to be detected as binary")
	}
	if IsBinary([]byte("plain utf-8 text\n")) {
		t.Error("expected plain UTF-8 to be non-binary")
	}
}

func TestRedactorBaselineAndTruncatedPEM(t *testing.T) {
	red, err := NewRedactor(true, []string{`CUSTOM-[0-9]{6}`})
	if err != nil {
		t.Fatalf("NewRedactor failed: %v", err)
	}

	sample := strings.Join([]string{
		"aws=AKIAIOSFODNN7EXAMPLE and temp=ASIAIOSFODNN7EXAMPLE",
		"gh=ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"ant=sk-ant-api03-1234567890abcdefghijklmnop",
		"jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"Authorization: Bearer supersecretbearertoken",
		"Cookie: session_id=abc123def456",
		"https://admin:hunter2@db.internal/app",
		`{"password": "my-db-password"}`,
		"custom=CUSTOM-987654",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234567890truncated_without_end",
	}, "\n")

	out, count := red.RedactString(sample)
	if count < 9 {
		t.Fatalf("expected >= 9 redactions, got %d (out=%s)", count, out)
	}
	leaks := []string{
		"MIIEowIBAAKCAQEA",
		"AKIAIOSFODNN7EXAMPLE",
		"ASIAIOSFODNN7EXAMPLE",
		"ghp_1234567890",
		"sk-ant-api03",
		"supersecretbearertoken",
		"session_id=abc123",
		"hunter2",
		"my-db-password",
		"CUSTOM-987654",
	}
	for _, leak := range leaks {
		if strings.Contains(out, leak) {
			t.Errorf("secret %q leaked after redaction: %s", leak, out)
		}
	}

	// Verify NUL bytes do not bypass secret redaction.
	nulPayload := []byte("bin\x00AKIAIOSFODNN7EXAMPLE\x00Authorization: Bearer topsecret999\n")
	redactedBin, binCount := red.RedactBytes(nulPayload)
	if binCount < 2 {
		t.Fatalf("expected >= 2 redactions in NUL payload, got %d (%q)", binCount, string(redactedBin))
	}
	if bytes.Contains(redactedBin, []byte("AKIAIOSFODNN7EXAMPLE")) || bytes.Contains(redactedBin, []byte("topsecret999")) {
		t.Fatalf("secret leaked across NUL byte boundary: %q", string(redactedBin))
	}
}

func TestPinnedTLS13HandshakeAndVerifyCertEdges(t *testing.T) {
	srvID, err := GenerateEphemeralIdentity("remote")
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := GenerateEphemeralIdentity("host")
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := GenerateEphemeralIdentity("other")
	if err != nil {
		t.Fatal(err)
	}

	// Edge cases in VerifyPeerEd25519Cert.
	if _, _, err := VerifyPeerEd25519Cert(nil, nil); err == nil {
		t.Fatal("expected error for 0 peer certs")
	}
	if _, _, err := VerifyPeerEd25519Cert([][]byte{cliID.DER, srvID.DER}, nil); err == nil {
		t.Fatal("expected error for 2 peer certs")
	}
	if _, _, err := VerifyPeerEd25519Cert([][]byte{{}}, nil); err == nil {
		t.Fatal("expected error for empty DER")
	}
	if _, _, err := VerifyPeerEd25519Cert([][]byte{make([]byte, maxPeerCertDERBytes+1)}, nil); err == nil {
		t.Fatal("expected error for oversized DER")
	}
	if _, _, err := VerifyPeerEd25519Cert([][]byte{[]byte("not-der")}, nil); err == nil {
		t.Fatal("expected error for malformed DER")
	}
	if fp, _, err := VerifyPeerEd25519Cert([][]byte{cliID.DER}, &cliID.Fingerprint); err != nil || fp != cliID.Fingerprint {
		t.Fatalf("expected matching pin to pass: fp=%x err=%v", fp, err)
	}

	runHandshake := func(sCfg, cCfg *tls.Config) (error, error) {
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()
		srvTLS := tls.Server(c1, sCfg)
		cliTLS := tls.Client(c2, cCfg)
		_ = srvTLS.SetDeadline(time.Now().Add(2 * time.Second))
		_ = cliTLS.SetDeadline(time.Now().Add(2 * time.Second))
		sErrCh := make(chan error, 1)
		go func() { sErrCh <- srvTLS.Handshake() }()
		cErr := cliTLS.Handshake()
		if cErr != nil {
			_ = c2.Close()
		}
		sErr := <-sErrCh
		return sErr, cErr
	}

	// Pinned mutual TLS 1.3 succeeds when both pins match.
	sErr, cErr := runHandshake(
		ServerTLSConfig(srvID, func() ([32]byte, bool) { return cliID.Fingerprint, true }),
		ClientTLSConfig(cliID, &srvID.Fingerprint),
	)
	if sErr != nil || cErr != nil {
		t.Fatalf("expected pinned TLS 1.3 handshake to succeed, got sErr=%v cErr=%v", sErr, cErr)
	}

	// Wrong client cert rejected by server pin.
	sErr, cErr = runHandshake(
		ServerTLSConfig(srvID, func() ([32]byte, bool) { return cliID.Fingerprint, true }),
		ClientTLSConfig(otherID, &srvID.Fingerprint),
	)
	if sErr == nil {
		t.Fatalf("expected server pin to reject unpinned client cert (cErr=%v)", cErr)
	}

	// Wrong server cert rejected by client pin.
	sErr, cErr = runHandshake(
		ServerTLSConfig(otherID, func() ([32]byte, bool) { return cliID.Fingerprint, true }),
		ClientTLSConfig(cliID, &srvID.Fingerprint),
	)
	if cErr == nil {
		t.Fatalf("expected client pin to reject unpinned server cert (sErr=%v)", sErr)
	}
}

func TestSanitizeMultilinePreviewAstralAndSASAlphabet(t *testing.T) {
	// SanitizeMultiline prefixes lines, truncates excess lines, and escapes controls.
	ml := SanitizeMultiline("line1\nline2\x1b[31m\nline3\nline4", "> ", 2, 100)
	if !strings.Contains(ml, "> line1\n> line2\\x1b[31m\n> ... (2 more line(s))") {
		t.Fatalf("unexpected SanitizeMultiline output: %q", ml)
	}
	capped := SanitizeMultiline("abcdefghij", "|", 10, 5)
	if capped != "|abcde" {
		t.Fatalf("expected byte-capped SanitizeMultiline '|abcde', got %q", capped)
	}

	// FormatShellPreview quotes spaces, empty tokens, single quotes, and escapes controls.
	prev := FormatShellPreview("echo", []string{"hello world", "", "a'b", "ok", "\x1b"})
	wantPrev := `echo 'hello world' '' 'a'\''b' ok '\x1b'`
	if prev != wantPrev {
		t.Fatalf("FormatShellPreview = %q, want %q", prev, wantPrev)
	}

	// EscapeJSONControls encodes astral format rune U+E0001 as a UTF-16 surrogate pair.
	astral := []byte("{\"s\":\"a\U000E0001b\"}")
	esc := string(EscapeJSONControls(astral))
	if !strings.Contains(esc, `\udb40\udc01`) {
		t.Fatalf("expected UTF-16 surrogate escape for U+E0001, got %q", esc)
	}

	// formatSAS60 extracts bits 59..0 using Crockford Base32 without ambiguous chars.
	allOnes := []byte{0x0F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if got := formatSAS60(allOnes); got != "ZZZZ-ZZZZ-ZZZZ" {
		t.Fatalf("formatSAS60(bits 59..0 all 1) = %q, want ZZZZ-ZZZZ-ZZZZ", got)
	}
	topFourOnly := []byte{0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if got := formatSAS60(topFourOnly); got != "0000-0000-0000" {
		t.Fatalf("formatSAS60(bits 63..60 only) = %q, want 0000-0000-0000", got)
	}
	for i := 0; i < 64; i++ {
		var sample [8]byte
		binary.BigEndian.PutUint64(sample[:], uint64(0x123456789ABCDEF0)^uint64(i*0x0101010101010101))
		sas := formatSAS60(sample[:])
		if len(sas) != 14 || sas[4] != '-' || sas[9] != '-' {
			t.Fatalf("bad SAS shape: %q", sas)
		}
		for _, ch := range strings.ReplaceAll(sas, "-", "") {
			if !strings.ContainsRune(crockfordAlphabet, ch) || strings.ContainsRune("ILOU", ch) {
				t.Fatalf("SAS %q contains disallowed character %q", sas, ch)
			}
		}
	}
}
