package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/pbkdf2"
)

func GenerateSecretEndpoint(w http.ResponseWriter, req *http.Request) {
	random := make([]byte, 10)
	rand.Read(random)
	secret := base32.StdEncoding.EncodeToString(random)
	json.NewEncoder(w).Encode(secret)
}

// Random generate string
func GetRandomString(n int) string {
	const alphanum = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	var bytes = make([]byte, n)
	rand.Read(bytes)
	for i, b := range bytes {
		bytes[i] = alphanum[b%byte(len(alphanum))]
	}
	return string(bytes)
}

func EncodePassword(rawPwd string, salt string) string {
	pwd := pbkdf2.Key([]byte(rawPwd), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(pwd)
}

func VerifyPassword(rawPwd, encodedPwd string) bool {
	var salt, encoded string
	salt = encodedPwd[:15]
	encoded = encodedPwd[16:]

	return EncodePassword(rawPwd, salt) == encoded
}
