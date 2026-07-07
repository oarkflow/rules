package condition

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/oarkflow/bcl"
)

type SignedBundle struct {
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature"`
	SignerID  string          `json:"signer_id"`
	Algorithm string          `json:"algorithm"`
	SignedAt  time.Time       `json:"signed_at"`
	Thumbprint string         `json:"thumbprint,omitempty"`
}

type BundleSigner struct {
	privateKey crypto.Signer
	signerID   string
	publicKey  crypto.PublicKey
}

func NewBundleSigner(pemKey []byte, signerID string) (*BundleSigner, error) {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	var key crypto.Signer
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "EC PRIVATE KEY":
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		key, ok = k.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key does not implement crypto.Signer")
		}
	case "ED25519 PRIVATE KEY":
		if len(block.Bytes) != ed25519.SeedSize {
			return nil, fmt.Errorf("invalid ed25519 private key length")
		}
		key = ed25519.NewKeyFromSeed(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type %q", block.Type)
	}
	return &BundleSigner{privateKey: key, signerID: signerID, publicKey: key.Public()}, nil
}

func (bs *BundleSigner) SignBundle(payload any) (*SignedBundle, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(data)
	sig, err := bs.privateKey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, err
	}
	algo := algorithmName(bs.privateKey)
	thumbprint, _ := publicKeyThumbprint(bs.publicKey)
	return &SignedBundle{
		Payload:    data,
		Signature:  base64.StdEncoding.EncodeToString(sig),
		SignerID:   bs.signerID,
		Algorithm:  algo,
		SignedAt:   time.Now().UTC(),
		Thumbprint: thumbprint,
	}, nil
}

type BundleVerifier struct {
	publicKeys map[string]crypto.PublicKey
}

func NewBundleVerifier() *BundleVerifier {
	return &BundleVerifier{publicKeys: map[string]crypto.PublicKey{}}
}

func (bv *BundleVerifier) AddPublicKey(signerID string, pemKey []byte) error {
	block, _ := pem.Decode(pemKey)
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}
	var pub crypto.PublicKey
	switch block.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return err
		}
		pub = k
	case "RSA PUBLIC KEY":
		k, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return err
		}
		pub = k
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		pub = cert.PublicKey
	default:
		return fmt.Errorf("unsupported public key type %q", block.Type)
	}
	bv.publicKeys[signerID] = pub
	return nil
}

func (bv *BundleVerifier) Verify(bundle *SignedBundle) (bool, error) {
	pub, ok := bv.publicKeys[bundle.SignerID]
	if !ok {
		return false, fmt.Errorf("unknown signer %q", bundle.SignerID)
	}
	digest := sha256.Sum256(bundle.Payload)
	sig, err := base64.StdEncoding.DecodeString(bundle.Signature)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(p, crypto.SHA256, digest[:], sig); err != nil {
			return false, err
		}
		return true, nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(p, digest[:], sig) {
			return false, fmt.Errorf("ecdsa signature verification failed")
		}
		return true, nil
	case ed25519.PublicKey:
		if !ed25519.Verify(p, digest[:], sig) {
			return false, fmt.Errorf("ed25519 signature verification failed")
		}
		return true, nil
	default:
		return false, fmt.Errorf("unsupported public key type %T", pub)
	}
}

func algorithmName(key crypto.Signer) string {
	switch key.(type) {
	case *rsa.PrivateKey:
		return "RSA-SHA256"
	case *ecdsa.PrivateKey:
		return "ECDSA-SHA256"
	case ed25519.PrivateKey:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func publicKeyThumbprint(pub crypto.PublicKey) (string, error) {
	data, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

func (s *Service) VerifyBundle(ctx context.Context, definition string) (bool, error) {
	record, err := s.store.GetActiveDefinition(ctx, definition, s.cfg.Environment)
	if err != nil {
		return false, err
	}
	bundleRaw, ok := record.Metadata["signed_bundle"]
	if !ok {
		return false, fmt.Errorf("definition %q has no signed bundle metadata", definition)
	}
	data, err := json.Marshal(bundleRaw)
	if err != nil {
		return false, err
	}
	var bundle SignedBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return false, err
	}
	verifier := NewBundleVerifier()
	if err := verifier.AddPublicKey(bundle.SignerID, s.trustStorePublicKey(bundle.SignerID)); err != nil {
		return false, err
	}
	return verifier.Verify(&bundle)
}

func (s *Service) trustStorePublicKey(signerID string) []byte {
	if raw, ok := s.cfg.Runtime.Metadata["trusted_public_key_"+signerID]; ok {
		if key, ok := raw.(string); ok {
			return []byte(key)
		}
	}
	return nil
}

type SignatureVerificationPolicy struct {
	Required        bool     `json:"required,omitempty"`
	AllowedSigners  []string `json:"allowed_signers,omitempty"`
	MinimumAlgo     string   `json:"minimum_algo,omitempty"`
	RejectExpired   bool     `json:"reject_expired,omitempty"`
	MaxAge          string   `json:"max_age,omitempty"`
}

func verifyPolicySignature(program *bcl.DecisionProgram, bundle *SignedBundle, policy SignatureVerificationPolicy) error {
	if policy.Required && bundle == nil {
		return fmt.Errorf("signature verification required but bundle is not signed")
	}
	if policy.AllowedSigners != nil {
		allowed := false
		for _, signer := range policy.AllowedSigners {
			if signer == bundle.SignerID {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("signer %q is not in the allowed signers list", bundle.SignerID)
		}
	}
	if policy.RejectExpired && policy.MaxAge != "" {
		d, err := time.ParseDuration(policy.MaxAge)
		if err == nil && time.Since(bundle.SignedAt) > d {
			return fmt.Errorf("signature expired (signed at %s, max age %s)", bundle.SignedAt.Format(time.RFC3339), policy.MaxAge)
		}
	}
	return nil
}

func addSignatureMetadata(metadata map[string]any, bundle *SignedBundle) map[string]any {
	if metadata == nil {
		metadata = map[string]any{}
	}
	sigInfo := map[string]any{
		"signer_id":   bundle.SignerID,
		"algorithm":   bundle.Algorithm,
		"signed_at":   bundle.SignedAt.Format(time.RFC3339Nano),
		"signature":   bundle.Signature,
		"thumbprint":  bundle.Thumbprint,
	}
	if bundle.Payload != nil {
		sigInfo["payload_hash"] = sha256Digest(bundle.Payload)
	}
	metadata["signed_bundle"] = sigInfo
	return metadata
}

func sha256Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

func stringsFromAnyV(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s := strings.TrimSpace(fmt.Sprint(item)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return x
	case string:
		if strings.TrimSpace(x) == "" {
			return nil
		}
		return []string{strings.TrimSpace(x)}
	default:
		return nil
	}
}
