package state

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/teambition/crypto-go"
)

func TestCryptoState(t *testing.T) {
	t.Run("Sign and Verify should work", func(t *testing.T) {
		assert := assert.New(t)

		fmt.Println(Sign([]byte("my key"), ""))
		fmt.Println(Sign([]byte("my key"), "some message"))

		key := crypto.RandN(16)
		state := Sign(key, "")
		assert.Equal(64, len(state))
		assert.True(Verify(key, "", state, time.Second))
		assert.True(Verify(key, "", state, time.Second))
		assert.False(Verify(key, "abc", state, time.Second))
		assert.False(Verify(key, "", state[0:5], time.Second))
		assert.False(Verify(key, "", state+"1", time.Second))
		assert.False(Verify(crypto.RandN(12), "", state, time.Second))

		state1 := Sign(key, "")
		assert.Equal(64, len(state1))
		assert.True(Verify(key, "", state1, time.Second))
		assert.NotEqual(state, state1)

		state = Sign(key, "cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4")
		assert.True(Verify(key, "cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4", state, time.Second))
		assert.True(Verify(key, "cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4", state, time.Second))
	})

	t.Run("should verify failure when expired", func(t *testing.T) {
		assert := assert.New(t)

		key := crypto.RandN(16)
		state := Sign(key, "")
		assert.True(Verify(key, "", state, time.Second))
		assert.False(Verify(key, "abc", state, time.Second))
		assert.False(Verify(key, "", state[0:5], time.Second))
		assert.False(Verify(key, "", state+"1", time.Second))
		assert.False(Verify(crypto.RandN(12), "", state, time.Second))
		time.Sleep(2 * time.Second)
		assert.False(Verify(key, "", state, time.Second))

		state = Sign(key, "cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4")
		assert.True(Verify(key, "cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4", state, time.Second))
		time.Sleep(2 * time.Second)
		assert.False(Verify(key, "cb374f9a1d2c3e8e56fe76c7e0770531eed27c89beae9de4", state, time.Second))
	})
}
