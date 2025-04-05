package crypto

// Crypto 定义加密接口
type Crypto interface {
	Encrypt(data []byte, key []byte) ([]byte, error)
	Decrypt(data []byte, key []byte) ([]byte, error)
}
