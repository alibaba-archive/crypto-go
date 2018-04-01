package cipher

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/crypto-go"
)

var byteNil []byte

func TestCryptoCipherBox(t *testing.T) {
	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		publicKeyA, privateKeyA := GenerateKey()
		publicKeyB, privateKeyB := GenerateKey()
		myBoxA, err := NewBox(publicKeyB, privateKeyA)
		assert.Nil(err)
		myBoxB, err := NewBox(publicKeyA, privateKeyB)
		assert.Nil(err)
		myBoxC, err := NewBox(publicKeyA, privateKeyA)
		assert.Nil(err)

		_, err = NewBox(publicKeyA, "privateKeyA")
		assert.NotNil(err)
		_, err = NewBox("publicKeyA", privateKeyA)
		assert.NotNil(err)
		_, err = NewBox(publicKeyA[1:], privateKeyA)
		assert.NotNil(err)
		_, err = NewBox(publicKeyA, privateKeyA[1:])
		assert.NotNil(err)

		encrypted, err := myBoxA.Encrypt(byteNil)
		assert.Nil(err)
		data, err := myBoxB.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		encrypted, err = myBoxC.Encrypt(byteNil)
		assert.Nil(err)
		data, err = myBoxC.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		encrypted, err = myBoxB.Encrypt([]byte("Hello! 中国"))
		assert.Nil(err)
		data, err = myBoxA.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		encrypted2, err := myBoxA.Encrypt([]byte("Hello! 中国"))
		assert.NotEqual(encrypted, encrypted2)
		assert.Nil(err)
		data, err = myBoxB.Decrypt(encrypted2)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		encrypted2, err = myBoxC.Encrypt([]byte("Hello! 中国"))
		assert.NotEqual(encrypted, encrypted2)
		assert.Nil(err)
		data, err = myBoxC.Decrypt(encrypted2)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		data, err = myBoxC.Decrypt(append(encrypted2[0:len(encrypted2)-1], encrypted2[len(encrypted2)-1]+1))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = myBoxC.Decrypt(encrypted2[0:10])
		assert.NotNil(err)
		assert.Nil(data)

		data, err = myBoxC.Decrypt(encrypted2[0:32])
		assert.NotNil(err)
		assert.Nil(data)
	})

	t.Run("should work with EncryptToBase64 and DecryptFromBase64", func(t *testing.T) {
		assert := assert.New(t)

		publicKeyA, privateKeyA := GenerateKey()
		publicKeyB, privateKeyB := GenerateKey()
		myBoxA, err := NewBox(publicKeyB, privateKeyA)
		assert.Nil(err)
		myBoxB, err := NewBox(publicKeyA, privateKeyB)
		assert.Nil(err)
		myBoxC, err := NewBox(publicKeyA, privateKeyA)
		assert.Nil(err)

		cipherData, err := EncryptToBase64(myBoxA, byteNil)
		assert.Nil(err)
		data, err := DecryptFromBase64(myBoxB, cipherData)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		cipherData, err = EncryptToBase64(myBoxB, []byte("Hello! 中国"))
		assert.Nil(err)
		data, err = DecryptFromBase64(myBoxA, cipherData)
		assert.Nil(err)
		assert.Equal([]byte("Hello! 中国"), data)

		cipherData, err = EncryptToBase64(myBoxC, []byte("Hello! 中国"))
		assert.Nil(err)
		data, err = DecryptFromBase64(myBoxC, cipherData)
		assert.Nil(err)
		assert.Equal([]byte("Hello! 中国"), data)

		data, err = DecryptFromBase64(myBoxC, cipherData+"1")
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(myBoxC, strings.ToLower(cipherData))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(myBoxC, cipherData[:len(cipherData)-10])
		assert.NotNil(err)
		assert.Nil(data)
	})
}

func TestCryptoCipherSalsa20(t *testing.T) {
	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		key := crypto.RandN(32)
		mySalsa20, err := NewSalsa20(key)
		assert.Nil(err)

		_, err = NewSalsa20(key[1:])
		assert.NotNil(err)

		encrypted, err := mySalsa20.Encrypt(byteNil)
		assert.Nil(err)
		data, err := mySalsa20.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		encrypted, err = mySalsa20.Encrypt([]byte("Hello! 中国"))
		assert.Nil(err)
		data, err = mySalsa20.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		encrypted2, err := mySalsa20.Encrypt([]byte("Hello! 中国"))
		assert.NotEqual(encrypted, encrypted2)
		assert.Nil(err)
		data, err = mySalsa20.Decrypt(encrypted2)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		data, err = mySalsa20.Decrypt(append(encrypted[0:len(encrypted)-1], encrypted[len(encrypted)-1]+1))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = mySalsa20.Decrypt(encrypted[0:10])
		assert.NotNil(err)
		assert.Nil(data)

		data, err = mySalsa20.Decrypt(encrypted[0:32])
		assert.NotNil(err)
		assert.Nil(data)
	})

	t.Run("should work with EncryptToBase64 and DecryptFromBase64", func(t *testing.T) {
		assert := assert.New(t)

		key := crypto.RandN(32)
		mySalsa20, err := NewSalsa20(key)
		assert.Nil(err)

		cipherData, err := EncryptToBase64(mySalsa20, byteNil)
		assert.Nil(err)
		data, err := DecryptFromBase64(mySalsa20, cipherData)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		cipherData, err = EncryptToBase64(mySalsa20, []byte("Hello! 中国"))
		assert.Nil(err)
		data, err = DecryptFromBase64(mySalsa20, cipherData)
		assert.Nil(err)
		assert.Equal([]byte("Hello! 中国"), data)

		data, err = DecryptFromBase64(mySalsa20, cipherData+"1")
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(mySalsa20, strings.ToLower(cipherData))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(mySalsa20, cipherData[:len(cipherData)-10])
		assert.NotNil(err)
		assert.Nil(data)
	})
}

func TestCryptoCipherAES(t *testing.T) {
	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		salt := crypto.RandN(16)
		key := crypto.SHA256Hmac(salt, []byte("test key"))
		myAES, err := NewAES(salt, key)
		assert.Nil(err)

		encrypted, err := myAES.Encrypt(byteNil)
		assert.Nil(err)
		data, err := myAES.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		encrypted, err = myAES.Encrypt([]byte("Hello! 中国"))
		assert.Nil(err)
		data, err = myAES.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		encrypted2, err := myAES.Encrypt([]byte("Hello! 中国"))
		assert.NotEqual(encrypted, encrypted2)
		assert.Nil(err)
		data, err = myAES.Decrypt(encrypted2)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		data, err = myAES.Decrypt(append(encrypted[0:len(encrypted)-1], encrypted[len(encrypted)-1]+1))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = myAES.Decrypt(encrypted[0:10])
		assert.NotNil(err)
		assert.Nil(data)
	})

	t.Run("should work with EncryptToBase64 and DecryptFromBase64", func(t *testing.T) {
		assert := assert.New(t)

		myAES, err := NewAES(nil, []byte("test key"))
		assert.Nil(err)

		cipherData, err := EncryptToBase64(myAES, byteNil)
		assert.Nil(err)
		data, err := DecryptFromBase64(myAES, cipherData)
		assert.Nil(err)
		assert.Equal(byteNil, data)

		cipherData, err = EncryptToBase64(myAES, []byte("Hello! 中国"))
		assert.Nil(err)
		data, err = DecryptFromBase64(myAES, cipherData)
		assert.Nil(err)
		assert.Equal([]byte("Hello! 中国"), data)

		data, err = DecryptFromBase64(myAES, cipherData+"1")
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(myAES, strings.ToLower(cipherData))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(myAES, cipherData[:len(cipherData)-10])
		assert.NotNil(err)
		assert.Nil(data)
	})
}
