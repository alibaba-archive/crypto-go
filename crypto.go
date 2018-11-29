package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"hash"
)

// Version -
const Version = "3.0.1"

// Equal compares two []byte for equality without leaking timing information.
//
//  fmt.Println(crypto.Equal([]byte("123"), []byte("123")))
//  fmt.Println(crypto.Equal([]byte("123"), []byte("1234")))
//
func Equal(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Rand fill rand bytes.
func Rand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		panic("crypto-go: rand.Read() failed, " + err.Error())
	}
}

// RandN return rand bytes by given size.
//
//  fmt.Println(crypto.RandN(16))
//
func RandN(size int) []byte {
	b := make([]byte, size)
	Rand(b)
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
