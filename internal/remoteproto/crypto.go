package remoteproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const (
	ekmLabel         = "agbox-remote-pair-v1"
	transcriptDomain = "agbox-transcript-v1"
	commitDomain     = "agbox-commit-v1"
	sasDomain        = "agbox-sas-v1"
	sessionDomain    = "agbox-sid-v1"

	maxPeerCertDERBytes = 4096

	// Crockford Base32 alphabet avoids visually ambiguous characters (I, L, O, U).
	crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

// EphemeralIdentity holds an in-memory Ed25519 TLS certificate and its SHA-256 fingerprint.
type EphemeralIdentity struct {
	Cert        tls.Certificate
	DER         []byte
	Fingerprint [32]byte
}

// GenerateEphemeralIdentity creates an in-memory Ed25519 keypair and self-signed certificate.
func GenerateEphemeralIdentity(commonName string) (EphemeralIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return EphemeralIdentity{}, fmt.Errorf("generate Ed25519 key: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return EphemeralIdentity{}, fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now().UTC()
	if commonName == "" {
		commonName = "agbox-remote"
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return EphemeralIdentity{}, fmt.Errorf("create self-signed certificate: %w", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return EphemeralIdentity{}, fmt.Errorf("parse self-signed certificate: %w", err)
	}
	return EphemeralIdentity{
		Cert: tls.Certificate{
			Certificate: [][]byte{der},
			PrivateKey:  priv,
			Leaf:        parsed,
		},
		DER:         der,
		Fingerprint: sha256.Sum256(der),
	}, nil
}

// VerifyPeerEd25519Cert checks that rawCerts contains one bounded Ed25519 certificate.
// When pinned is non-nil, it also requires an exact constant-time SHA-256 DER match.
func VerifyPeerEd25519Cert(rawCerts [][]byte, pinned *[32]byte) ([32]byte, []byte, error) {
	var zero [32]byte
	if len(rawCerts) != 1 {
		return zero, nil, fmt.Errorf("expected exactly 1 peer certificate, got %d", len(rawCerts))
	}
	der := rawCerts[0]
	if len(der) == 0 || len(der) > maxPeerCertDERBytes {
		return zero, nil, fmt.Errorf("peer certificate size %d outside allowed bounds", len(der))
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return zero, nil, fmt.Errorf("parse peer certificate: %w", err)
	}
	if _, ok := cert.PublicKey.(ed25519.PublicKey); !ok {
		return zero, nil, errors.New("peer certificate public key must be Ed25519")
	}
	fp := sha256.Sum256(der)
	if pinned != nil && !ConstantTimeEqual32(fp, *pinned) {
		return zero, nil, errors.New("peer certificate fingerprint does not match pinned identity")
	}
	return fp, der, nil
}

// ServerTLSConfig constructs a TLS 1.3 mTLS config for the remote target daemon.
// pinnedClientFP returns (fp, true) once paired so non-pinned clients fail at handshake.
func ServerTLSConfig(id EphemeralIdentity, pinnedClientFP func() ([32]byte, bool)) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{id.Cert},
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			var pinned *[32]byte
			if pinnedClientFP != nil {
				if fp, ok := pinnedClientFP(); ok {
					pinned = &fp
				}
			}
			_, _, err := VerifyPeerEd25519Cert(rawCerts, pinned)
			return err
		},
	}
}

// ClientTLSConfig constructs a TLS 1.3 mTLS config for the host broker.
// Pass a non-nil pinnedServerFP on reconnect to enforce exact remote cert pinning.
func ClientTLSConfig(id EphemeralIdentity, pinnedServerFP *[32]byte) *tls.Config {
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		SessionTicketsDisabled: true,
		Certificates:           []tls.Certificate{id.Cert},
		InsecureSkipVerify:     true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, _, err := VerifyPeerEd25519Cert(rawCerts, pinnedServerFP)
			return err
		},
	}
}

// ExportPairingEKM exports 32 bytes of TLS 1.3 channel-bound keying material.
func ExportPairingEKM(conn *tls.Conn) ([]byte, error) {
	st := conn.ConnectionState()
	if !st.HandshakeComplete {
		return nil, errors.New("TLS handshake is not complete")
	}
	if st.Version != tls.VersionTLS13 {
		return nil, fmt.Errorf("expected TLS 1.3, got version 0x%x", st.Version)
	}
	return st.ExportKeyingMaterial(ekmLabel, nil, 32)
}

// RandomBytes32 generates 32 cryptographically random bytes.
func RandomBytes32() ([32]byte, error) {
	var out [32]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, fmt.Errorf("read random bytes: %w", err)
	}
	return out, nil
}

// RandomHex16 generates a 128-bit lowercase hexadecimal identifier.
func RandomHex16() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("read random ID: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func writeLenPrefixed(h interface{ Write([]byte) (int, error) }, data []byte) {
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(data)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write(data)
}

// ComputeTranscript hashes the length-prefixed pairing transcript components.
func ComputeTranscript(ekm, hostCertDER, remoteCertDER, rawHelloR, rawHelloH []byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(transcriptDomain))
	writeLenPrefixed(h, ekm)
	writeLenPrefixed(h, hostCertDER)
	writeLenPrefixed(h, remoteCertDER)
	writeLenPrefixed(h, rawHelloR)
	writeLenPrefixed(h, rawHelloH)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// ComputeCommit computes Move 1's SHA-256 commitment over nonceH and transcript.
func ComputeCommit(nonceH [32]byte, transcript [32]byte) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(commitDomain))
	_, _ = h.Write(nonceH[:])
	_, _ = h.Write(transcript[:])
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// DeriveSASAndSession derives the 60-bit XXXX-XXXX-XXXX Crockford Base32 SAS
// and the 256-bit session ID after Vaudenay 3-move commit-reveal completes.
func DeriveSASAndSession(transcript [32]byte, nonceH, nonceR [32]byte) (string, [32]byte) {
	sasHash := sha256.New()
	_, _ = sasHash.Write([]byte(sasDomain))
	_, _ = sasHash.Write(transcript[:])
	_, _ = sasHash.Write(nonceH[:])
	_, _ = sasHash.Write(nonceR[:])
	sasDigest := sasHash.Sum(nil)

	sidHash := sha256.New()
	_, _ = sidHash.Write([]byte(sessionDomain))
	_, _ = sidHash.Write(transcript[:])
	_, _ = sidHash.Write(nonceH[:])
	_, _ = sidHash.Write(nonceR[:])
	var sid [32]byte
	sidHash.Sum(sid[:0])

	return formatSAS60(sasDigest[:8]), sid
}

func formatSAS60(eightBytes []byte) string {
	val := binary.BigEndian.Uint64(eightBytes)
	// Extract bits 59..0 into 12 Crockford Base32 characters (XXXX-XXXX-XXXX).
	var b strings.Builder
	b.Grow(14)
	for i := 0; i < 12; i++ {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		shift := uint(59 - i*5)
		idx := (val >> (shift - 4)) & 0x1F
		b.WriteByte(crockfordAlphabet[idx])
	}
	return b.String()
}

// ConstantTimeEqual32 compares two 32-byte digests in constant time.
func ConstantTimeEqual32(a, b [32]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// DecodeHex32 parses a 64-character hex string into a 32-byte array.
func DecodeHex32(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(raw) != 32 {
		return out, errors.New("expected 64-character hexadecimal digest")
	}
	copy(out[:], raw)
	return out, nil
}
