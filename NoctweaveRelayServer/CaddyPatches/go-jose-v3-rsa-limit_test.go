package jose

import (
	"crypto/rsa"
	"math/big"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3/json"
)

func TestNoctweaveRSALimits(t *testing.T) {
	key := rawJSONWebKey{
		N: newBuffer(new(big.Int).Lsh(big.NewInt(1), 4096).Bytes()),
		E: newBuffer([]byte{1, 0, 1}),
		D: newBuffer([]byte{3}),
		P: newBuffer([]byte{3}),
		Q: newBuffer([]byte{3}),
	}
	if _, err := key.rsaPublicKey(); err == nil || !strings.Contains(err.Error(), "modulus too large") {
		t.Fatalf("oversized public RSA modulus was accepted: %v", err)
	}
	if _, err := key.rsaPrivateKey(); err == nil || !strings.Contains(err.Error(), "modulus too large") {
		t.Fatalf("oversized private RSA modulus was accepted: %v", err)
	}
	key.N = newBuffer(new(big.Int).Lsh(big.NewInt(1), 4095).Bytes())
	if _, err := key.rsaPublicKey(); err != nil {
		t.Fatalf("4096-bit public RSA modulus was rejected: %v", err)
	}

	key.N = newBuffer(new(big.Int).Lsh(big.NewInt(1), 2048).Bytes())
	key.P = newBuffer(new(big.Int).Lsh(big.NewInt(1), 16383).Bytes())
	if _, err := key.rsaPrivateKey(); err == nil || !strings.Contains(err.Error(), "p * q != n") {
		t.Fatalf("oversized RSA prime reached expensive validation: %v", err)
	}
}

func TestNoctweaveEmbeddedPrivateJWK(t *testing.T) {
	private := `{"kty":"RSA","n":"AQ","e":"AQAB","d":"AQ","p":"AQ","q":"AQ"}`
	protected := newBuffer([]byte(`{"alg":"RS256","jwk":` + private + `}`)).base64()
	protectedAlg := newBuffer([]byte(`{"alg":"RS256"}`)).base64()
	payload := newBuffer([]byte("payload")).base64()
	signature := newBuffer([]byte("signature")).base64()
	messages := map[string]string{
		"compact protected":     protected + "." + payload + "." + signature,
		"flattened protected":   `{"protected":"` + protected + `","payload":"` + payload + `","signature":"` + signature + `"}`,
		"general protected":     `{"payload":"` + payload + `","signatures":[{"protected":"` + protected + `","signature":"` + signature + `"}]}`,
		"flattened unprotected": `{"protected":"` + protectedAlg + `","header":{"jwk":` + private + `},"payload":"` + payload + `","signature":"` + signature + `"}`,
		"general unprotected":   `{"payload":"` + payload + `","signatures":[{"protected":"` + protectedAlg + `","header":{"jwk":` + private + `},"signature":"` + signature + `"}]}`,
	}
	for name, message := range messages {
		t.Run(name, func(t *testing.T) {
			_, err := ParseSigned(message)
			if err == nil || !strings.Contains(err.Error(), "JWK contains private parameters") {
				t.Fatalf("private JWK was parsed before rejection: %v", err)
			}
		})
	}

	// Public embedded JWKs and direct trusted private JWK unmarshaling remain valid.
	publicJSON, err := json.Marshal(JSONWebKey{Key: &rsaTestKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	publicProtected := newBuffer([]byte(`{"alg":"RS256","jwk":` + string(publicJSON) + `}`)).base64()
	if _, err := ParseSigned(publicProtected + "." + payload + "." + signature); err != nil {
		t.Fatalf("public embedded JWK was rejected: %v", err)
	}
	privateJSON, err := json.Marshal(JSONWebKey{Key: rsaTestKey})
	if err != nil {
		t.Fatal(err)
	}
	var direct JSONWebKey
	if err := json.Unmarshal(privateJSON, &direct); err != nil {
		t.Fatalf("direct private JWK unmarshal was rejected: %v", err)
	}
	if _, ok := direct.Key.(*rsa.PrivateKey); !ok {
		t.Fatalf("direct private JWK had unexpected type %T", direct.Key)
	}
}

func TestNoctweavePrivateEPK(t *testing.T) {
	epk := json.RawMessage(`{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","d":"AQAB"}`)
	_, err := (rawHeader{headerEPK: &epk}).getEPK()
	if err == nil || !strings.Contains(err.Error(), "JWK contains private parameters") {
		t.Fatalf("private EPK was parsed before rejection: %v", err)
	}
}

func TestNoctweavePrivateJWEHeaders(t *testing.T) {
	private := `{"kty":"RSA","n":"AQ","e":"AQAB","d":"AQ","p":"AQ","q":"AQ"}`
	privateEPK := `{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB","d":"AQAB"}`
	publicJSON, err := json.Marshal(JSONWebKey{Key: &rsaTestKey.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	protected := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A128GCM"}`)).base64()
	protectedPublic := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A128GCM","jwk":` + string(publicJSON) + `}`)).base64()
	protectedPrivate := newBuffer([]byte(`{"alg":"RSA-OAEP","enc":"A128GCM","jwk":` + private + `}`)).base64()
	trailer := `,"iv":"dGVzdA","ciphertext":"dGVzdA","tag":"dGVzdA"}`
	messages := map[string]string{
		"compact protected":    protectedPrivate + ".dGVzdA.dGVzdA.dGVzdA.dGVzdA",
		"flattened recipient":  `{"protected":"` + protected + `","header":{"jwk":` + private + `},"encrypted_key":"dGVzdA"` + trailer,
		"general recipient":    `{"protected":"` + protected + `","recipients":[{"header":{"jwk":` + private + `},"encrypted_key":"dGVzdA"}]` + trailer,
		"general private EPK":  `{"protected":"` + protected + `","recipients":[{"header":{"epk":` + privateEPK + `},"encrypted_key":"dGVzdA"}]` + trailer,
		"general unprotected":  `{"protected":"` + protected + `","unprotected":{"jwk":` + private + `},"recipients":[{"encrypted_key":"dGVzdA"}]` + trailer,
		"shadowed unprotected": `{"protected":"` + protectedPublic + `","unprotected":{"jwk":` + private + `},"recipients":[{"encrypted_key":"dGVzdA"}]` + trailer,
	}
	for name, message := range messages {
		t.Run(name, func(t *testing.T) {
			_, err := ParseEncrypted(message)
			if err == nil || !strings.Contains(err.Error(), "JWK contains private parameters") {
				t.Fatalf("private JWE key material was parsed before rejection: %v", err)
			}
		})
	}
	publicMessage := `{"protected":"` + protectedPublic + `","recipients":[{"encrypted_key":"dGVzdA"}]` + trailer
	if _, err := ParseEncrypted(publicMessage); err != nil {
		t.Fatalf("public JWE JWK was rejected: %v", err)
	}
}
