package crypto

import (
	"crypto/md5"
	"encoding/hex"
	"io"
)

type MD5 struct {
}

var UseMD5 = new(MD5)

func (ist *MD5) Encrypt(input, key string) string {
	hash := md5.New()
	if key != "" {
		_, _ = io.WriteString(hash, key)
	}
	_, _ = io.WriteString(hash, input)
	return hex.EncodeToString(hash.Sum(nil))
}

func (ist *MD5) Compare(input, salt, hash string) bool {
	return ist.Encrypt(input, salt) == hash
}
