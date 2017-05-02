package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// Equal compares two []byte for equality without leaking timing information.
//
//  fmt.Println(crypto.Equal([]byte("123"), []byte("123")))
//  fmt.Println(crypto.Equal([]byte("123"), []byte("1234")))
//
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// RandN return rand bytes by given size.
//
//  fmt.Println(crypto.RandN(16))
//
func RandN(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read() failed: " + err.Error())
	}
	return b
}

// HashSum returns hash result by given hash function and data
//
//  fmt.Println(crypto.HashSum(md5.New, []byte("hello")))
//  fmt.Println(crypto.HashSum(sha256.New, []byte("hello")))
//
func HashSum(h func() hash.Hash, data []byte) []byte {
	hs := h()
	hs.Write(data)
	return hs.Sum(nil)
}

// HmacSum returns Keyed-Hash result by given hash function, key and data
//
//  fmt.Println(crypto.HmacSum(md5.New, []byte("my key"), []byte("hello")))
//  fmt.Println(crypto.HmacSum(sha256.New, []byte("my key"), []byte("hello")))
//
func HmacSum(h func() hash.Hash, key, data []byte) []byte {
	hs := hmac.New(h, key)
	hs.Write(data)
	return hs.Sum(nil)
}

// SHA256Sum returns SHA256 hash result by given data
//
//  fmt.Println(crypto.SHA256Sum([]byte("hello")))
//
func SHA256Sum(data []byte) []byte {
	return HashSum(sha256.New, data)
}

// SHA256Hmac returns SHA256 Keyed-Hash result by given key and data
//
//  fmt.Println(crypto.SHA256Hmac([]byte("my key"), []byte("hello")))
//
func SHA256Hmac(key, data []byte) []byte {
	return HmacSum(sha256.New, key, data)
}

// AESEncrypt encrypt data using AES-256 with CTR Mode
//
//  fmt.Println(crypto.AESEncrypt([]byte("my salt"), []byte("my key"), []byte("hello")))
//  fmt.Println(crypto.AESEncrypt(nil, []byte("my key"), []byte("hello"))) // no salt
//
func AESEncrypt(salt, key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(SHA256Hmac(key, salt))
	if err != nil {
		return nil, err
	}

	cipherData := make([]byte, aes.BlockSize+len(data))
	iv := cipherData[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(cipherData[aes.BlockSize:], data)
	return append(cipherData, HmacSum(sha1.New, cipherData, data)...), nil
}

// AESDecrypt decrypt data that encrypted by AESEncrypt
//
//  fmt.Println(crypto.AESDecrypt([]byte("my salt"), []byte("my key"), cipherData))
//  fmt.Println(crypto.AESDecrypt(nil, []byte("my key"), cipherData)) // no salt
//
func AESDecrypt(salt, key, cipherData []byte) ([]byte, error) {
	if len(cipherData) < aes.BlockSize+sha1.Size {
		return nil, errors.New("invalid cipher data")
	}
	block, err := aes.NewCipher(SHA256Hmac(key, salt))
	if err != nil {
		return nil, err
	}

	checkSum := cipherData[len(cipherData)-sha1.Size:]
	cipherData = cipherData[:len(cipherData)-sha1.Size]
	data := make([]byte, len(cipherData)-aes.BlockSize)
	stream := cipher.NewCTR(block, cipherData[:aes.BlockSize])
	stream.XORKeyStream(data, cipherData[aes.BlockSize:])

	if !Equal(HmacSum(sha1.New, cipherData, data), checkSum) {
		return nil, errors.New("invalid cipher data")
	}
	return data, nil
}

// AESEncryptStr encrypt data using AES-256 with CTR Mode
//
//  fmt.Println(crypto.AESEncryptStr([]byte("my salt"), "my key", "hello"))
//  fmt.Println(crypto.AESEncryptStr(nil, "my key", "hello")) // no salt
//
func AESEncryptStr(salt []byte, key, plainText string) (string, error) {
	data, err := AESEncrypt(salt, []byte(key), []byte(plainText))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// AESDecryptStr decrypt data that encrypted by AESDecryptStr
//
//  fmt.Println(crypto.AESDecryptStr([]byte("my salt"), "my key", cipherData))
//  fmt.Println(crypto.AESDecryptStr(nil, "my key", cipherData)) // no salt
//
func AESDecryptStr(salt []byte, key, cipherText string) (string, error) {
	cipherData, err := base64.RawURLEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}

	data, err := AESDecrypt(salt, []byte(key), cipherData)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// SignPass generates a string checkPass with PBKDF2 & SHA-3 by the user' id and pass.
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
// recommended salt length >= 16 bytes
// default iter count is 12480
// default result length is 64
//
//  fmt.Println(crypto.SignPass([]byte("salt..."), "user_id", "user_password"))
//  fmt.Println(crypto.SignPass([]byte("salt..."), "user_id", "user_password"), 1024) // iterCount == 1024
//  fmt.Println(crypto.SignPass([]byte("salt..."), "user_id", "user_password"), 1024, 32)
//
func SignPass(salt []byte, id, pass string, args ...int) (checkPass string) {
	b := signPass(salt, RandN(8), HmacSum(sha3.New256, []byte(pass), []byte(id)), args...)
	return base64.RawURLEncoding.EncodeToString(b)
}

func signPass(salt, iv, pass []byte, args ...int) []byte {
	iterCount := 12480
	keylen := 64
	if len(args) > 0 && args[0] >= 1000 {
		iterCount = args[0]
	}
	if len(args) > 1 && args[1] >= 14 { // recommended minimum length
		keylen = args[1]
	}
	b := pbkdf2.Key(append(pass, iv...), salt, iterCount, keylen, sha3.New512)
	return append(b, iv...)
}

// VerifyPass verify user' id and password that generated by SignPass
//
//  fmt.Println(crypto.VerifyPass([]byte("salt..."), "user_id", "user_password", checkPass))
//
func VerifyPass(salt []byte, id, pass, checkPass string, args ...int) bool {
	a, err := base64.RawURLEncoding.DecodeString(checkPass)
	if err != nil || len(a) < 22 { // l4 + 8
		return false
	}
	return Equal(a, signPass(salt, a[len(a)-8:], HmacSum(sha3.New256, []byte(pass), []byte(id)), args...))
}

// SignState generates a state string signed with SHA1.
// It is useful for OAUTH2 or Web hook callback.
//
//  fmt.Println(SignState([]byte("my key"), "")
//  // 2932b947b464b598643b46ab11ebb3deb3f45dcb78e107a4.1489725353
//  fmt.Println(SignState([]byte("my key"), "admin")
//  // cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4.1489725353
//
func SignState(key []byte, uid string) string {
	ts := time.Now().Unix()
	iv := RandN(4)
	suffix := fmt.Sprintf(`%x.%d`, iv, ts)
	return signState(key, uid+suffix) + suffix
}

func signState(key []byte, str string) string {
	return hex.EncodeToString(HmacSum(sha1.New, key, []byte(str)))
}

// VerifyState Verify state that generated by SignState.
//
//  fmt.Println(VerifyState([]byte("my key"), "", state, 60* time.Second)
//
func VerifyState(key []byte, uid, state string, expire time.Duration) bool {
	if len(state) < 50 {
		return false
	}
	i, err := strconv.ParseInt(state[49:], 10, 64)
	if err != nil || (i+int64(expire)/1e9) < time.Now().Unix() {
		return false
	}
	return state[0:40] == signState(key, uid+state[40:])
}

// Rotating is used to verify data through a rotating credential system,
// in which new server keys can be added and old ones removed regularly,
// without invalidating client credentials.
//
//  var err error
//  var claims josejwt.Claims
//  index := Rotating(keys).Verify(func(key interface{}) bool {
//  	if err = jwtToken.Validate(key, method); err == nil {
//  		claims = jwtToken.Claims()
//  		return true
//  	}
//  	return false
//  })
//
type Rotating []interface{}

// Verify verify with fn and keys, if Verify failure, it return -1, otherwise the index of key.
func (r Rotating) Verify(fn func(interface{}) bool) (index int) {
	for i, key := range r {
		if fn(key) {
			return i
		}
	}
	return -1
}

// RotatingStr is similar to Rotating.
type RotatingStr []string

// Verify verify with fn and keys, if Verify failure, it return -1, otherwise the index of key.
func (r RotatingStr) Verify(fn func(string) bool) (index int) {
	for i, key := range r {
		if fn(key) {
			return i
		}
	}
	return -1
}

// RotatingBytes is similar to Rotating.
type RotatingBytes [][]byte

// Verify verify with fn and keys, if Verify failure, it return -1, otherwise the index of key.
func (r RotatingBytes) Verify(fn func([]byte) bool) (index int) {
	for i, key := range r {
		if fn(key) {
			return i
		}
	}
	return -1
}
