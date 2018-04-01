package password

import (
	"encoding/base64"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"

	"github.com/teambition/crypto-go"
)

// Sign generates a string checkPass with PBKDF2 & SHA-3 by the user' id and pass.
// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
// recommended salt length >= 16 bytes
// default iter count is 12480
// default result length is 64
//
//  fmt.Println(Sign([]byte("salt..."), "user_id", "user_password"))
//  fmt.Println(Sign([]byte("salt..."), "user_id", "user_password"), 1024) // iterCount == 1024
//  fmt.Println(Sign([]byte("salt..."), "user_id", "user_password"), 1024, 32)
//
func Sign(salt []byte, id, pass string, args ...int) (checkPass string) {
	b := sign(salt, crypto.RandN(8), crypto.HmacSum(sha3.New256, []byte(pass), []byte(id)), args...)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Verify verify user' id and password that generated by Sign
//
//  fmt.Println(Verify([]byte("salt..."), "user_id", "user_password", checkPass))
//
func Verify(salt []byte, id, pass, checkPass string, args ...int) bool {
	a, err := base64.RawURLEncoding.DecodeString(checkPass)
	if err != nil || len(a) < 22 { // l4 + 8
		return false
	}
	return crypto.Equal(a, sign(salt, a[len(a)-8:], crypto.HmacSum(sha3.New256, []byte(pass), []byte(id)), args...))
}

func sign(salt, iv, pass []byte, args ...int) []byte {
	iterCount := 12480
	keylen := 64
	if len(args) > 0 && args[0] >= 1000 {
		iterCount = args[0]
	}
	if len(args) > 1 && args[1] >= 14 { // recommended minimum length
		keylen = args[1]
	}
	b := pbkdf2.Key(append(pass, iv...), salt, iterCount, keylen, sha3.New512)
	return append(b, iv...)
}

// Password -
type Password struct {
	salt []byte
	args []int
}

// New returns a Password instance with given salt.
//
//  pw := New([]byte("salt..."))
func New(salt []byte, args ...int) *Password {
	return &Password{salt: salt, args: args}
}

// Sign sign password
//
//  fmt.Println(pw.Sign("user_id", "user_password"))
func (p *Password) Sign(id, pass string) (checkPass string) {
	return Sign(p.salt, id, pass, p.args...)
}

// Verify verify password
//
//  fmt.Println(pw.Verify("user_id", "user_password"), checkPass)
func (p *Password) Verify(id, pass, checkPass string) bool {
	return Verify(p.salt, id, pass, checkPass, p.args...)
}
