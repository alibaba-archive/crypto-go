package signature

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"strconv"

	"github.com/teambition/crypto-go"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/sha3"
)

const (
	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64
)

// Sign - sign a message with Hmac sha3 512.
func Sign(secretKey, message []byte) (sig []byte) {
	return crypto.HmacSum(sha3.New512, secretKey, message)
}

// Verify - verify message for Sign
func Verify(secretKey, message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	return crypto.Equal(sig, Sign(secretKey, message))
}

// SignPrivate - sign a message with public-key signature ed25519
func SignPrivate(privateKey, message []byte) (sig []byte) {
	return ed25519.Sign(ed25519.PrivateKey(privateKey), message)
}

// VerifyPublic - verify message for SignPrivate
func VerifyPublic(publicKey, message, sig []byte) bool {
	if len(sig) != SignatureSize || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), message, sig)
}

// Keys - struct for Sign and Verify with HmacSum & sha3.New256
type Keys [][]byte

// Sign - sign a message with HmacSum & sha3.New256
func (k Keys) Sign(message []byte) []byte {
	if len(k) == 0 {
		return nil
	}
	return crypto.HmacSum(sha3.New256, k[0], message)
}

// Verify - verify message with HmacSum & sha3.New256
func (k Keys) Verify(message, sig []byte) bool {
	if len(sig) != 32 {
		return false
	}
	for _, key := range k {
		if crypto.Equal(sig, crypto.HmacSum(sha3.New256, key, message)) {
			return true
		}
	}
	return false
}

// Seal - Seal a message with HmacSum&sha3.New256
func (k Keys) Seal(message []byte) []byte {
	sig := k.Sign(message)
	return append(sig, message...)
}

// Open - Open a message with HmacSum&sha3.New256
func (k Keys) Open(message []byte) ([]byte, bool) {
	if len(message) > 32 {
		data := message[32:]
		if k.Verify(data, message[:32]) {
			// should return a copy data
			return append(make([]byte, 0, len(data)), data...), true
		}
	}
	return nil, false
}

// KeyPair - struct for Sign and Verify with ed25519
type KeyPair struct {
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
}

// Sign - sign a message with public-key signature ed25519
func (k *KeyPair) Sign(message []byte) (sig []byte) {
	return ed25519.Sign(k.privateKey, message)
}

// Verify - verify message for Sign
func (k *KeyPair) Verify(message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(k.publicKey, message, sig)
}

// GenerateKey generates a public/private key pair using entropy from rand.
// the keys is encoded by base64.RawURLEncoding
func GenerateKey() (publicKey, privateKey string) {
	public, private, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(public), base64.RawURLEncoding.EncodeToString(private)
}

// KeyPairFrom converts key encoded by base64.RawURLEncoding to KeyPair.
// privateKey is used for sign, publicKey is used for verify.
// if privateKey omits, sign method can't be used.
func KeyPairFrom(publicKey string, privateKey ...string) (*KeyPair, error) {
	keyPair := KeyPair{}
	public, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	if l := len(public); l != ed25519.PublicKeySize {
		return nil, errors.New("crypto-go: bad ed25519 public key length: " + strconv.Itoa(l))
	}
	keyPair.publicKey = ed25519.PublicKey(public)

	if len(privateKey) > 0 {
		private, err := base64.RawURLEncoding.DecodeString(privateKey[0])
		if err != nil {
			return nil, err
		}
		if l := len(private); l != ed25519.PrivateKeySize {
			return nil, errors.New("crypto-go: bad ed25519 private key length: " + strconv.Itoa(l))
		}
		if !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
			return nil, errors.New("crypto-go: bad ed25519 public/private key pair")
		}
		keyPair.privateKey = ed25519.PrivateKey(private)
	}
	return &keyPair, nil
}

// KeyPairs -
type KeyPairs []*KeyPair

// Sign - sign a message with ed25519
func (k KeyPairs) Sign(message []byte) (sig []byte) {
	if len(k) == 0 {
		return nil
	}
	return k[0].Sign(message)
}

// Verify - verify message with ed25519
func (k KeyPairs) Verify(message, sig []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	for _, key := range k {
		if key.Verify(message, sig) {
			return true
		}
	}
	return false
}

// Seal - Seal a message with ed25519
func (k KeyPairs) Seal(message []byte) []byte {
	sig := k.Sign(message)
	return append(sig, message...)
}

// Open - Open a message with ed25519
func (k KeyPairs) Open(message []byte) ([]byte, bool) {
	if len(message) > SignatureSize {
		data := message[SignatureSize:]
		if k.Verify(data, message[:SignatureSize]) {
			return append(make([]byte, 0, len(data)), data...), true
		}
	}
	return nil, false
}
