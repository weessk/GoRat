package crypto

import (
	"crypto/rand"
)

func isDebuggerPresent() bool {
	return false
}

func memoryObfuscator(data []byte) {
	for i := range data {
		data[i] ^= 0xAA
	}
	for i := range data {
		data[i] ^= 0xAA
	}
}

func XORDecrypt(data []byte, key byte) string {
	if isDebuggerPresent() {
		return ""
	}
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	memoryObfuscator(dataCopy)
	memoryObfuscator(dataCopy)

	result := make([]byte, len(dataCopy))
	for i, b := range dataCopy {
		result[i] = b ^ key
	}

	return string(result)
}

func AdvancedXOREncrypt(input string, key byte) []byte {
	data := []byte(input)

	for i := range data {
		data[i] ^= key
	}

	for i := range data {
		data[i] ^= byte(i % 255)
	}

	noise := make([]byte, len(data))
	rand.Read(noise)
	for i := range data {
		data[i] ^= noise[i] ^ key
	}

	return data
}

func SecureWipe(data []byte) {
	for i := range data {
		data[i] = 0x00
	}
	for i := range data {
		data[i] = 0xFF
	}
	for i := range data {
		data[i] = 0x00
	}
}
