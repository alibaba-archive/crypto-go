package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/sha3"
)

func TestCrypto(t *testing.T) {
	t.Run("Equal", func(t *testing.T) {
		assert := assert.New(t)

		assert.True(Equal([]byte("123"), []byte("123")))
		assert.False(Equal([]byte("123"), []byte("abc")))
	})

	t.Run("RandN", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal(0, len(RandN(0)))
		assert.Equal(8, len(RandN(8)))
		assert.Equal(15, len(RandN(15)))
	})

	t.Run("SHA256Sum", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			hex.EncodeToString(SHA256Sum([]byte{})))
		assert.Equal("72726d8818f693066ceb69afa364218b692e62ea92b385782363780f47529c21",
			hex.EncodeToString(SHA256Sum([]byte("中文"))))
	})

	t.Run("HashSum", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("d41d8cd98f00b204e9800998ecf8427e",
			hex.EncodeToString(HashSum(md5.New, []byte{})))
		assert.Equal("a7bac2239fcdcb3a067903d8077c4a07",
			hex.EncodeToString(HashSum(md5.New, []byte("中文"))))

		assert.Equal("da39a3ee5e6b4b0d3255bfef95601890afd80709",
			hex.EncodeToString(HashSum(sha1.New, []byte{})))
		assert.Equal("7be2d2d20c106eee0836c9bc2b939890a78e8fb3",
			hex.EncodeToString(HashSum(sha1.New, []byte("中文"))))

		assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			hex.EncodeToString(HashSum(sha256.New, []byte{})))
		assert.Equal("72726d8818f693066ceb69afa364218b692e62ea92b385782363780f47529c21",
			hex.EncodeToString(HashSum(sha256.New, []byte("中文"))))

		assert.Equal("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
			hex.EncodeToString(HashSum(sha3.New256, []byte{})))
		assert.Equal("ac5305da3d18be1aed44aa7c70ea548da243a59a5fd546f489348fd5718fb1a0",
			hex.EncodeToString(HashSum(sha3.New256, []byte("中文"))))
	})

	t.Run("HmacSum", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("74e6f7298a9c2d168935f58c001bad88",
			hex.EncodeToString(HmacSum(md5.New, nil, []byte{})))
		assert.Equal("74e6f7298a9c2d168935f58c001bad88",
			hex.EncodeToString(HmacSum(md5.New, []byte{}, []byte{})))
		assert.Equal("d2b8aee3a7b860d93005cf5f0d239ea1",
			hex.EncodeToString(HmacSum(md5.New, nil, []byte("中文"))))
		assert.Equal("4a23aaec863f1bd0974d4e83910d3e17",
			hex.EncodeToString(HmacSum(md5.New, []byte("abc"), []byte{})))
		assert.Equal("22c7b79bbee5f8ac93959c36ce73a763",
			hex.EncodeToString(HmacSum(md5.New, []byte("abc"), []byte("中文"))))

		assert.Equal("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
			hex.EncodeToString(HmacSum(sha256.New, nil, []byte{})))
		assert.Equal("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
			hex.EncodeToString(HmacSum(sha256.New, []byte{}, []byte{})))
		assert.Equal("52f32e44183ef72271e707e57875a044b7039233ce4193e8284817712939afb3",
			hex.EncodeToString(HmacSum(sha256.New, nil, []byte("中文"))))
		assert.Equal("e2636077506729a8f61aff2441332e40e844a8ad44489efd80210ea6d1f51088",
			hex.EncodeToString(HmacSum(sha256.New, []byte("abc"), []byte{})))
		assert.Equal("e61f53e7c7932bf37ecf8b704866549c03fc7250cd1d3708bef92c02d09cd9fe",
			hex.EncodeToString(HmacSum(sha256.New, []byte("abc"), []byte("中文"))))

		assert.Equal("e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea",
			hex.EncodeToString(HmacSum(sha3.New256, nil, []byte{})))
		assert.Equal("e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea",
			hex.EncodeToString(HmacSum(sha3.New256, []byte{}, []byte{})))
		assert.Equal("f316ce909c86a8f51c0df568a9782c2b934ba406da8646026c22977b7273a5c9",
			hex.EncodeToString(HmacSum(sha3.New256, nil, []byte("中文"))))
		assert.Equal("c9b2ba2847b0057387fe8949261677346dbd319c2148947cbe81bc681b0f81db",
			hex.EncodeToString(HmacSum(sha3.New256, []byte("abc"), []byte{})))
		assert.Equal("7eeab728f66a2fe8c2df8059e0929e3eaf12fdad43210a299d008086b7bc116e",
			hex.EncodeToString(HmacSum(sha3.New256, []byte("abc"), []byte("中文"))))
	})

	t.Run("SHA256Hmac", func(t *testing.T) {
		assert := assert.New(t)
		assert.Equal(32, len(SHA256Hmac([]byte{}, []byte{})))
		assert.Equal(32, len(SHA256Hmac([]byte{}, []byte("test pass"))))
		assert.Equal(32, len(SHA256Hmac([]byte("admin"), []byte{})))
		assert.Equal(32, len(SHA256Hmac([]byte("admin"), []byte("中文"))))
	})

	t.Run("Rotating", func(t *testing.T) {
		assert := assert.New(t)

		keys := []interface{}{"a", "b", "c"}
		r := Rotating(keys)
		assert.Equal(-1, r.Verify(func(key interface{}) bool {
			return key.(string) == "x"
		}))
		assert.Equal(0, r.Verify(func(key interface{}) bool {
			return key.(string) == "a"
		}))
		assert.Equal(1, r.Verify(func(key interface{}) bool {
			return key.(string) == "b"
		}))
		assert.Equal(2, r.Verify(func(key interface{}) bool {
			return key.(string) == "c"
		}))
	})

	t.Run("RotatingStr", func(t *testing.T) {
		assert := assert.New(t)

		keys := []string{"a", "b", "c"}
		r := RotatingStr(keys)
		assert.Equal(-1, r.Verify(func(key string) bool {
			return key == "x"
		}))
		assert.Equal(0, r.Verify(func(key string) bool {
			return key == "a"
		}))
		assert.Equal(1, r.Verify(func(key string) bool {
			return key == "b"
		}))
		assert.Equal(2, r.Verify(func(key string) bool {
			return key == "c"
		}))
	})

	t.Run("RotatingBytes", func(t *testing.T) {
		assert := assert.New(t)

		keys := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
		r := RotatingBytes(keys)
		assert.Equal(-1, r.Verify(func(key []byte) bool {
			return string(key) == "x"
		}))
		assert.Equal(0, r.Verify(func(key []byte) bool {
			return string(key) == "a"
		}))
		assert.Equal(1, r.Verify(func(key []byte) bool {
			return string(key) == "b"
		}))
		assert.Equal(2, r.Verify(func(key []byte) bool {
			return string(key) == "c"
		}))
	})
}

// go test -bench=.
func BenchmarkSHA2(b *testing.B) {
	b.N = 1000000
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		HashSum(sha256.New, []byte{})
	}
}

func BenchmarkSHA3(b *testing.B) {
	b.N = 1000000
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		HashSum(sha3.New256, []byte{})
	}
}
