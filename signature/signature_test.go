package signature

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/crypto-go"
	"golang.org/x/crypto/ed25519"
)

func TestCryptoSignature(t *testing.T) {
	t.Run("Sign and Verify", func(t *testing.T) {
		assert := assert.New(t)
		key := crypto.RandN(16)

		sig := Sign(key, []byte("test message"))
		assert.Equal(SignatureSize, len(sig))
		assert.True(Verify(key, []byte("test message"), sig))
		assert.False(Verify(key[1:], []byte("test message"), sig))
		assert.False(Verify(key, []byte("test message1"), sig))
		assert.False(Verify(key, []byte("test message"), sig[1:]))
		assert.False(Verify(key, []byte("test message"), sig[:10]))

		sig = Sign(nil, []byte("test message"))
		assert.True(Verify(nil, []byte("test message"), sig))
		assert.False(Verify(key, []byte("test message"), sig))
	})

	t.Run("Keys", func(t *testing.T) {
		assert := assert.New(t)
		keys1 := Keys([][]byte{crypto.RandN(16)})
		keys2 := Keys([][]byte{crypto.RandN(32), keys1[0]})

		sig := keys1.Sign([]byte("test message"))
		assert.True(keys1.Verify([]byte("test message"), sig))
		assert.True(keys2.Verify([]byte("test message"), sig))
		assert.False(keys1.Verify([]byte("test message1"), sig))
		assert.False(keys1.Verify([]byte("test message"), sig[1:]))
		assert.False(keys1.Verify([]byte("test message"), sig[:10]))

		msg := []byte("你好，中国！")
		data := keys2.Seal(msg)
		v, ok := keys2.Open(data)
		assert.True(ok)
		assert.Equal(msg, v)
		assert.Equal(32+len(msg), len(data))

		v, ok = keys1.Open(msg)
		assert.False(ok)
		assert.Nil(v)
		v, ok = keys2.Open(msg[:len(msg)-10])
		assert.False(ok)
		assert.Nil(v)
	})

	t.Run("SignPrivate and VerifyPublic", func(t *testing.T) {
		assert := assert.New(t)
		public, private, _ := ed25519.GenerateKey(nil)

		sig := SignPrivate(private, []byte("test message"))
		assert.Equal(SignatureSize, len(sig))
		assert.True(VerifyPublic(public, []byte("test message"), sig))
		assert.False(VerifyPublic(public[1:], []byte("test message"), sig))
		assert.False(VerifyPublic(public, []byte("test message1"), sig))
		assert.False(VerifyPublic(public, []byte("test message"), sig[1:]))
		assert.False(VerifyPublic(public, []byte("test message"), sig[:10]))
	})

	t.Run("KeyPair", func(t *testing.T) {
		assert := assert.New(t)

		publicKey, privateKey := GenerateKey()
		pair1, err := KeyPairFrom(publicKey, privateKey)
		assert.Nil(err)
		pair2, err := KeyPairFrom(publicKey)
		assert.Nil(err)

		sig := pair1.Sign([]byte("test message"))
		assert.True(pair1.Verify([]byte("test message"), sig))
		assert.False(pair1.Verify([]byte("test message1"), sig))
		assert.False(pair1.Verify([]byte("test message"), sig[1:]))
		assert.False(pair1.Verify([]byte("test message"), sig[:10]))
		assert.True(pair2.Verify([]byte("test message"), sig))
	})

	t.Run("GenerateKey and KeyPairFrom", func(t *testing.T) {
		assert := assert.New(t)

		publicKey, privateKey := GenerateKey()
		_, err := KeyPairFrom(publicKey, privateKey)
		assert.Nil(err)
		_, err = KeyPairFrom(publicKey)
		assert.Nil(err)

		_, err = KeyPairFrom("publicKey", "privateKey")
		assert.NotNil(err)

		_, err = KeyPairFrom(publicKey[2:], privateKey)
		assert.NotNil(err)

		_, err = KeyPairFrom(publicKey, privateKey[2:])
		assert.NotNil(err)

		publicKey2, privateKey2 := GenerateKey()
		_, err = KeyPairFrom(publicKey, privateKey2)
		assert.NotNil(err)

		_, err = KeyPairFrom(publicKey2, privateKey)
		assert.NotNil(err)
	})

	t.Run("KeyPairs", func(t *testing.T) {
		assert := assert.New(t)
		// publicKey, privateKey := GenerateKey()
		KeyPair1, err := KeyPairFrom(GenerateKey())
		assert.Nil(err)
		KeyPair2, err := KeyPairFrom(GenerateKey())
		assert.Nil(err)

		keyPairs1 := KeyPairs([]*KeyPair{KeyPair1})
		keyPairs2 := KeyPairs([]*KeyPair{KeyPair2, KeyPair1})

		sig := keyPairs1.Sign([]byte("test message"))
		assert.True(keyPairs1.Verify([]byte("test message"), sig))
		assert.True(keyPairs2.Verify([]byte("test message"), sig))
		assert.False(keyPairs1.Verify([]byte("test message1"), sig))
		assert.False(keyPairs1.Verify([]byte("test message"), sig[1:]))
		assert.False(keyPairs1.Verify([]byte("test message"), sig[:10]))

		msg := []byte("你好，中国！")
		data := keyPairs2.Seal(msg)
		v, ok := keyPairs2.Open(data)
		assert.True(ok)
		assert.Equal(msg, v)
		assert.Equal(64+len(msg), len(data))

		v, ok = keyPairs1.Open(msg)
		assert.False(ok)
		assert.Nil(v)
		v, ok = keyPairs2.Open(msg[:len(msg)-10])
		assert.False(ok)
		assert.Nil(v)
	})
}
