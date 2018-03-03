package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/crypto-go"
)

func TestCryptoPassword(t *testing.T) {
	t.Run("Sign and Verify", func(t *testing.T) {
		assert := assert.New(t)
		salt := crypto.RandN(16)

		checkPass := Sign(salt, "admin", "test pass")
		assert.True(Verify(salt, "admin", "test pass", checkPass))
		assert.False(Verify(salt, "admin1", "test pass", checkPass))
		assert.False(Verify(salt, "admin", "test pass1", checkPass))
		assert.False(Verify(salt, "admin", "test pass", checkPass[1:]))
		assert.False(Verify(salt, "admin", "test pass", checkPass[:10]))

		checkPass = Sign(nil, "admin", "test pass")
		assert.True(Verify(nil, "admin", "test pass", checkPass))
		assert.False(Verify(salt, "admin", "test pass", checkPass))

		checkPass = Sign(salt, "admin", "test pass", 1025, 16)
		assert.True(Verify(salt, "admin", "test pass", checkPass, 1025, 16))
		assert.False(Verify(salt, "admin", "test pass", checkPass, 1024, 16))
	})
}
