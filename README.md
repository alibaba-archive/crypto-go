# Crypto-go

A functional crypto wrapper for go applications.

[![Build Status](http://img.shields.io/travis/teambition/crypto-go.svg?style=flat-square)](https://travis-ci.org/teambition/crypto-go)
[![Coverage Status](http://img.shields.io/coveralls/teambition/crypto-go.svg?style=flat-square)](https://coveralls.io/r/teambition/crypto-go)
[![License](http://img.shields.io/badge/license-mit-blue.svg?style=flat-square)](https://raw.githubusercontent.com/teambition/crypto-go/master/LICENSE)
[![GoDoc](http://img.shields.io/badge/go-documentation-blue.svg?style=flat-square)](http://godoc.org/github.com/teambition/crypto-go)

## Documentation

https://godoc.org/github.com/teambition/crypto-go

## API

```go
func Equal(a, b []byte) bool

func RandN(size int) []byte

func HashSum(h func() hash.Hash, data []byte) []byte
func HmacSum(h func() hash.Hash, key, data []byte) []byte

func SHA256Sum(data []byte) []byte
func SHA256Hmac(key, data []byte) []byte

func AESEncrypt(salt, key, data []byte) ([]byte, error)
func AESDecrypt(salt, key, cipherData []byte) ([]byte, error)

func AESEncryptStr(salt []byte, key, plainText string) (string, error)
func AESDecryptStr(salt []byte, key, cipherText string) (string, error)

func SignPass(salt []byte, id, pass string, args ...int) (checkPass string)
func VerifyPass(salt []byte, id, pass, checkPass string, args ...int) bool

func SignState(key []byte, uid string) string
func VerifyState(key []byte, uid, state string, expire time.Duration) bool

type Rotating []interface{}
func (r Rotating) Verify(fn func(interface{}) bool) (index int)

type RotatingStr []string
func (r RotatingStr) Verify(fn func(string) bool) (index int)

type RotatingBytes [][]byte
func (r RotatingBytes) Verify(fn func([]byte) bool) (index int)
```

## License

crypto-go is licensed under the [MIT](https://github.com/teambition/crypto-go/blob/master/LICENSE) license.
Copyright &copy; 2016-2017 [Teambition](https://www.teambition.com).