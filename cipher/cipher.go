package cipher

import (
	"crypto/aes"
	_cipher "crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"io"
	"strconv"

	"github.com/teambition/crypto-go"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// GenerateKey generates a public/private key pair using entropy from rand.
// the keys is encoded by base64.RawURLEncoding
func GenerateKey() (publicKey, privateKey string) {
	public, private, err := box.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(public[:]), base64.RawURLEncoding.EncodeToString(private[:])
}

// Box - nacl/box
type Box struct {
	sharedEncryptKey *[32]byte
}

// NewBox -
func NewBox(publicKey, privateKey string) (*Box, error) {
	public, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, err
	}
	if l := len(public); l != 32 {
		return nil, errors.New("crypto-go: bad curve25519 public key length: " + strconv.Itoa(l))
	}

	private, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	if l := len(private); l != 32 {
		return nil, errors.New("crypto-go: bad curve25519 private key length: " + strconv.Itoa(l))
	}

	pub := new([32]byte)
	copy(pub[:], public[:24])
	pri := new([32]byte)
	copy(pri[:], private[:24])
	sharedEncryptKey := new([32]byte)
	box.Precompute(sharedEncryptKey, pub, pri)
	return &Box{sharedEncryptKey}, nil
}

// Encrypt - recipientPublicKey, senderPrivateKey for Encrypt
func (b *Box) Encrypt(data []byte) ([]byte, error) {
	nonce := new([24]byte)
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return box.SealAfterPrecomputation(nonce[:], data, nonce, b.sharedEncryptKey), nil
}

// Decrypt - senderPublicKey, recipientPrivateKey for Decrypt
func (b *Box) Decrypt(encrypted []byte) ([]byte, error) {
	decryptNonce := new([24]byte)
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.OpenAfterPrecomputation(nil, encrypted[24:], decryptNonce, b.sharedEncryptKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

// NewSalsa20 -
func NewSalsa20(key []byte) (*Salsa20, error) {
	if l := len(key); l != 32 {
		return nil, errors.New("crypto-go: bad Salsa20 key length: " + strconv.Itoa(l))
	}

	secretKey := new([32]byte)
	copy(secretKey[:], key)
	return &Salsa20{secretKey}, nil
}

// Salsa20 - nacl/secretbox
type Salsa20 struct {
	secretKey *[32]byte
}

// Encrypt -
func (s *Salsa20) Encrypt(data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, s.secretKey)
	return encrypted, nil
}

// Decrypt =
func (s *Salsa20) Decrypt(encrypted []byte) ([]byte, error) {
	decryptNonce := new([24]byte)
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], decryptNonce, s.secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

// AES -
type AES struct {
	block _cipher.Block
}

// NewAES -
func NewAES(salt, key []byte) (*AES, error) {
	block, err := aes.NewCipher(crypto.SHA256Hmac(key, salt))
	if err != nil {
		return nil, err
	}
	return &AES{block}, nil
}

// Encrypt encrypt data using AES-256 with CTR Mode
//
//  fmt.Println(crypto.AESEncrypt([]byte("my salt"), []byte("my key"), []byte("hello")))
//  fmt.Println(crypto.AESEncrypt(nil, []byte("my key"), []byte("hello"))) // no salt
//
func (a *AES) Encrypt(data []byte) ([]byte, error) {
	cipherData := make([]byte, aes.BlockSize+len(data))
	iv := cipherData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := _cipher.NewCTR(a.block, iv)
	stream.XORKeyStream(cipherData[aes.BlockSize:], data)
	return append(cipherData, crypto.HmacSum(sha1.New, cipherData, data)...), nil
}

// Decrypt -
func (a *AES) Decrypt(encrypted []byte) ([]byte, error) {
	if len(encrypted) < aes.BlockSize+sha1.Size {
		return nil, errors.New("invalid cipher data")
	}

	checkSum := encrypted[len(encrypted)-sha1.Size:]
	encrypted = encrypted[:len(encrypted)-sha1.Size]
	data := make([]byte, len(encrypted)-aes.BlockSize)
	stream := _cipher.NewCTR(a.block, encrypted[:aes.BlockSize])
	stream.XORKeyStream(data, encrypted[aes.BlockSize:])

	if !crypto.Equal(crypto.HmacSum(sha1.New, encrypted, data), checkSum) {
		return nil, errors.New("invalid cipher data")
	}
	return data, nil
}

// EncryptToBase64 encrypt data using AES-256 with CTR Mode
//
//  fmt.Println(crypto.AESEncryptStr([]byte("my salt"), "my key", "hello"))
//  fmt.Println(crypto.AESEncryptStr(nil, "my key", "hello")) // no salt
//
func EncryptToBase64(c Cipher, msg []byte) (string, error) {
	data, err := c.Encrypt(msg)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecryptFromBase64 decrypt data that encrypted by AESDecryptStr
//
//  fmt.Println(crypto.AESDecryptStr([]byte("my salt"), "my key", cipherData))
//  fmt.Println(crypto.AESDecryptStr(nil, "my key", cipherData)) // no salt
//
func DecryptFromBase64(c Cipher, encrypted string) ([]byte, error) {
	cipherData, err := base64.RawURLEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}

	data, err := c.Decrypt(cipherData)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// Cipher -
type Cipher interface {
	// Encrypt encrypts the first block in src into dst.
	// Dst and src must overlap entirely or not at all.
	Encrypt([]byte) ([]byte, error)

	// Decrypt decrypts the first block in src into dst.
	// Dst and src must overlap entirely or not at all.
	Decrypt([]byte) ([]byte, error)
}
