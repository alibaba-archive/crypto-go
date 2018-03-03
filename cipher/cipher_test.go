package cipher

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/crypto-go"
)

func TestCryptoCipherAES(t *testing.T) {
	t.Run("should work", func(t *testing.T) {
		assert := assert.New(t)

		salt := crypto.RandN(16)
		key := crypto.SHA256Hmac(salt, []byte("test key"))
		aes, err := NewAES(salt, key)
		assert.Nil(err)

		encrypted, err := aes.Encrypt([]byte{})
		assert.Nil(err)
		data, err := aes.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal([]byte{}, data)

		encrypted, err = aes.Encrypt([]byte("Hello! 中国"))
		assert.Nil(err)
		data, err = aes.Decrypt(encrypted)
		assert.Nil(err)
		assert.Equal("Hello! 中国", string(data))

		data, err = aes.Decrypt(append(encrypted[0:len(encrypted)-1], encrypted[len(encrypted)-1]+1))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = aes.Decrypt(encrypted[0:10])
		assert.NotNil(err)
		assert.Nil(data)
	})

	t.Run("should work with EncryptToBase64 and DecryptFromBase64", func(t *testing.T) {
		assert := assert.New(t)

		aes, err := NewAES(nil, []byte("test key"))
		assert.Nil(err)

		cipherData, err := EncryptToBase64(aes, []byte(""))
		assert.Nil(err)
		data, err := DecryptFromBase64(aes, cipherData)
		assert.Nil(err)
		assert.Equal([]byte(""), data)

		cipherData, err = EncryptToBase64(aes, []byte("Hello! 中国"))
		assert.Nil(err)
		data, err = DecryptFromBase64(aes, cipherData)
		assert.Nil(err)
		assert.Equal([]byte("Hello! 中国"), data)

		data, err = DecryptFromBase64(aes, cipherData+"1")
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(aes, strings.ToLower(cipherData))
		assert.NotNil(err)
		assert.Nil(data)

		data, err = DecryptFromBase64(aes, cipherData[:len(cipherData)-10])
		assert.NotNil(err)
		assert.Nil(data)
	})
}
