package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type RSA struct{}

var UseRSA = new(RSA)

// Encrypt 使用 RSA 公钥加密数据
func (ist *RSA) Encrypt(data []byte, key []byte) ([]byte, error) {
	// 解析 RSA 公钥
	publicKey, err := ist.parseRSAPublicKey(key)
	if err != nil {
		return nil, err
	}
	// 使用 OAEP 填充方案进行加密
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, data, nil)
}

// Decrypt 使用 RSA 私钥解密数据
func (ist *RSA) Decrypt(data []byte, key []byte) ([]byte, error) {
	// 解析 RSA 私钥
	privateKey, err := ist.parseRSAPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// 使用 OAEP 填充方案进行解密
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, data, nil)
}

// 解析 PEM 格式的 RSA 公钥
func (ist *RSA) parseRSAPublicKey(key []byte) (*rsa.PublicKey, error) {
	// 解码 PEM 格式的公钥
	block, _ := pem.Decode(key)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("failed to decode PEM block containing public key")
	}
	// 解析公钥
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 断言类型为 RSA 公钥
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return publicKey, nil
}

// 解析 PEM 格式的 RSA 私钥
func (ist *RSA) parseRSAPrivateKey(key []byte) (*rsa.PrivateKey, error) {
	// 解码 PEM 格式的私钥
	block, _ := pem.Decode(key)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("failed to decode PEM block containing private key")
	}
	// 解析私钥
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
