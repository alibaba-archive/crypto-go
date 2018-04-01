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

	t.Run("Password", func(t *testing.T) {
		assert := assert.New(t)
		salt := crypto.RandN(16)

		password0 := New(salt)

		checkPass := password0.Sign("admin", "test pass")
		assert.True(password0.Verify("admin", "test pass", checkPass))
		assert.False(password0.Verify("admin1", "test pass", checkPass))
		assert.False(password0.Verify("admin", "test pass1", checkPass))
		assert.False(password0.Verify("admin", "test pass", checkPass[1:]))
		assert.False(password0.Verify("admin", "test pass", checkPass[:10]))

		password2 := New(salt, 1025)
		checkPass2 := password2.Sign("admin", "test pass")
		assert.True(password2.Verify("admin", "test pass", checkPass2))
		assert.False(password2.Verify("admin", "test pass", checkPass))
		assert.False(password2.Verify("admin1", "test pass", checkPass2))
		assert.False(password2.Verify("admin", "test pass1", checkPass2))

		password3 := New(salt, 1025, 16)
		checkPass3 := password3.Sign("admin", "test pass")
		assert.True(password3.Verify("admin", "test pass", checkPass3))
		assert.False(password3.Verify("admin", "test pass", checkPass))
		assert.False(password3.Verify("admin1", "test pass", checkPass3))
		assert.False(password3.Verify("admin", "test pass1", checkPass3))
	})
}
