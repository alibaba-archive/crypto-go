# Crypto-go

A functional crypto wrapper for go applications.

[![Build Status](http://img.shields.io/travis/teambition/crypto-go.svg?style=flat-square)](https://travis-ci.org/teambition/crypto-go)
[![Coverage Status](http://img.shields.io/coveralls/teambition/crypto-go.svg?style=flat-square)](https://coveralls.io/r/teambition/crypto-go)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/crypto-go/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/crypto-go)

## Documentation

https://godoc.org/github.com/teambition/crypto-go

## API

crypto "github.com/teambition/crypto-go":
```go
func Equal(a, b []byte) bool

func RandN(size int) []byte

func HashSum(h func() hash.Hash, data []byte) []byte
func HmacSum(h func() hash.Hash, key, data []byte) []byte

func SHA256Sum(data []byte) []byte
func SHA256Hmac(key, data []byte) []byte

type Rotating []interface{}
func (r Rotating) Verify(fn func(interface{}) bool) (index int)

type RotatingStr []string
func (r RotatingStr) Verify(fn func(string) bool) (index int)

type RotatingBytes [][]byte
func (r RotatingBytes) Verify(fn func([]byte) bool) (index int)
```

state "github.com/teambition/crypto-go/state":
```go
func Sign(key []byte, message string) string
func Verify(key []byte, message, state string, expire ...time.Duration) bool

func New(keys ...[]byte) (*States, error)
func (s *States) Sign(message string) string
func (s *States) Verify(message, state string, expire ...time.Duration) bool
```

signature "github.com/teambition/crypto-go/signature":
```go
func Sign(secretKey, message []byte) (sig []byte)
func Verify(secretKey, message, sig []byte) bool

func SignPrivate(privateKey, message []byte) (sig []byte)
func VerifyPublic(publicKey, message, sig []byte) bool

func GenerateKey() (publicKey, privateKey string)
func KeyPairFrom(publicKey string, privateKey ...string) (*KeyPair, error)

func (k *KeyPair) Sign(message []byte) (sig []byte)
func (k *KeyPair) Verify(message, sig []byte) bool
```

password "github.com/teambition/crypto-go/password":
```go
func Sign(salt []byte, id, pass string, args ...int) (checkPass string)
func Verify(salt []byte, id, pass, checkPass string, args ...int) bool

func New(salt []byte, args ...int) *Password
func (p *Password) Sign(id, pass string) (checkPass string)
func (p *Password) Verify(id, pass, checkPass string) bool
```

cipher "github.com/teambition/crypto-go/cipher":
```go
func GenerateKey() (publicKey, privateKey string)

func NewBox(publicKey, privateKey string) (*Box, error)
func (b *Box) Encrypt(data []byte) ([]byte, error)
func (b *Box) Decrypt(encrypted []byte) ([]byte, error)

func NewSalsa20(key []byte) (*Salsa20, error)
func (s *Salsa20) Encrypt(data []byte) ([]byte, error)
func (s *Salsa20) Decrypt(encrypted []byte) ([]byte, error)

func NewAES(salt, key []byte) (*AES, error)
func (a *AES) Encrypt(data []byte) ([]byte, error)
func (a *AES) Decrypt(encrypted []byte) ([]byte, error)

func EncryptToBase64(c Cipher, msg []byte) (string, error)
func DecryptFromBase64(c Cipher, encrypted string) ([]byte, error)
```

## License

crypto-go is licensed under the [MIT](https://github.com/teambition/crypto-go/blob/master/LICENSE) license.
Copyright &copy; 2016-2018 [Teambition](https://www.teambition.com).