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

// GenerateKey generates a public/private key pair for Box.
// the keys is encoded by base64.RawURLEncoding
func GenerateKey() (publicKey, privateKey string) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(public[:]), base64.RawURLEncoding.EncodeToString(private[:])
}

// Box use to encrypts/decrypts message base on public key infrastructure (nacl/box, curve25519&salsa20), it implemented Cipher insterface.
type Box struct {
	sharedEncryptKey *[32]byte
}

// NewBox returns Box instance
func NewBox(peersPublicKey, privateKey string) (*Box, error) {
	public, err := base64.RawURLEncoding.DecodeString(peersPublicKey)
	if err != nil {
		return nil, err
	}
	if l := len(public); l != 32 {
		return nil, errors.New("crypto-go: bad curve25519 peers public key length: " + strconv.Itoa(l))
	}

	private, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	if l := len(private); l != 32 {
		return nil, errors.New("crypto-go: bad curve25519 private key length: " + strconv.Itoa(l))
	}

	pub := new([32]byte)
	copy(pub[:], public)
	pri := new([32]byte)
	copy(pri[:], private)
	sharedEncryptKey := new([32]byte)
	box.Precompute(sharedEncryptKey, pub, pri)
	return &Box{sharedEncryptKey}, nil
}

// Encrypt encrypt data using Box
//
//  cipherData, err := myBox.Encrypt([]byte("hello"))
func (b *Box) Encrypt(data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return box.SealAfterPrecomputation(nonce[:], data, &nonce, b.sharedEncryptKey), nil
}

// Decrypt decrypt data using Box
//
//  message, err := myBox.Decrypt(cipherData)
func (b *Box) Decrypt(encrypted []byte) ([]byte, error) {
	var decryptNonce [24]byte
	if len(encrypted) < 24 {
		return nil, errors.New("invalid input")
	}
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := box.OpenAfterPrecomputation(nil, encrypted[24:], &decryptNonce, b.sharedEncryptKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

// Salsa20 use to encrypts/decrypts message with salsa20, it implemented Cipher insterface.
type Salsa20 struct {
	secretKey *[32]byte
}

// NewSalsa20 returns Salsa20 instance.
func NewSalsa20(key []byte) (*Salsa20, error) {
	if l := len(key); l != 32 {
		return nil, errors.New("crypto-go: bad Salsa20 key length: " + strconv.Itoa(l))
	}

	secretKey := new([32]byte)
	copy(secretKey[:], key)
	return &Salsa20{secretKey}, nil
}

// Encrypt encrypt data using Salsa20.
//
//  cipherData, err := mySalsa20.Encrypt([]byte("hello"))
func (s *Salsa20) Encrypt(data []byte) ([]byte, error) {
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}

	encrypted := secretbox.Seal(nonce[:], data, &nonce, s.secretKey)
	return encrypted, nil
}

// Decrypt decrypt data using Salsa20.
//
//  message, err := mySalsa20.Decrypt(cipherData)
func (s *Salsa20) Decrypt(encrypted []byte) ([]byte, error) {
	decryptNonce := new([24]byte)
	if len(encrypted) < 24 {
		return nil, errors.New("invalid input")
	}
	copy(decryptNonce[:], encrypted[:24])
	decrypted, ok := secretbox.Open(nil, encrypted[24:], decryptNonce, s.secretKey)
	if !ok {
		return nil, errors.New("decryption error")
	}
	return decrypted, nil
}

// AES use to encrypts/decrypts message with AES-256 with CTR Mode, it implemented Cipher insterface.
type AES struct {
	block _cipher.Block
}

// NewAES returns AES instance
//
// myAES := NewAES([]byte("my salt"), []byte("my key"))
func NewAES(salt, key []byte) (*AES, error) {
	block, err := aes.NewCipher(crypto.SHA256Hmac(key, salt))
	if err != nil {
		return nil, err
	}
	return &AES{block}, nil
}

// Encrypt encrypt data using AES.
//
//  cipherData, err := myAES.Encrypt([]byte("hello"))
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

// Decrypt decrypt data using AES.
//
//  message, err := myAES.Decrypt(cipherData)
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
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}

// EncryptToBase64 encrypt data with given Cipher and returns base64 string
//
//  cipherString, err = EncryptToBase64(myAES, []byte("Hello! 中国"))
//  cipherString, err = EncryptToBase64(myBox, []byte("Hello! 中国"))
//  cipherString, err = EncryptToBase64(mySalsa20, []byte("Hello! 中国"))
//
func EncryptToBase64(c Cipher, msg []byte) (string, error) {
	data, err := c.Encrypt(msg)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecryptFromBase64 decrypt base64 string data with given Cipher and returns massage
//
//  messsage, err = DecryptFromBase64(myAES, cipherString)
//  messsage, err = DecryptFromBase64(myBox, cipherString)
//  messsage, err = DecryptFromBase64(mySalsa20, cipherString)
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

// Cipher is using for EncryptToBase64 and DecryptFromBase64
type Cipher interface {
	// Encrypt encrypts the first block in src into dst.
	// Dst and src must overlap entirely or not at all.
	Encrypt([]byte) ([]byte, error)

	// Decrypt decrypts the first block in src into dst.
	// Dst and src must overlap entirely or not at all.
	Decrypt([]byte) ([]byte, error)
}
