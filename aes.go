package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// sha256 加密
func Sha256Key(key string) []byte {
	h := sha256.New()
	h.Write([]byte(key))
	newKey := h.Sum(nil)
	return newKey
}

// 进行 PKCS7 填充
func PKCS7Padding(src []byte) []byte {
	bs := aes.BlockSize
	length := len(src)
	if length == 0 {
		return nil
	}

	paddingSize := bs - len(src)%bs
	if paddingSize == 0 {
		paddingSize = bs
	}

	paddingText := bytes.Repeat([]byte{byte(paddingSize)}, paddingSize)
	return append(src, paddingText...)
}

// 移除 PKCS7 填充
func PKCS7UnPadding(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return nil
	}

	unpadding := int(src[length-1])
	if length-unpadding < 0 {
		return nil
	}
	return src[:(length - unpadding)]
}

// 加密
func AesEncrypt(text, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}

	newText := []byte(text)
	newText = PKCS7Padding(newText)
	blockMode := cipher.NewCBCEncrypter(block, newKey[:16])
	cryptText := make([]byte, len(newText))
	blockMode.CryptBlocks(cryptText, newText)
	return base64.StdEncoding.EncodeToString(cryptText), nil
}

// 解密
func AesDecrypt(text, key string) (string, error) {
	newKey := Sha256Key(key)
	block, err := aes.NewCipher(newKey)
	if err != nil {
		return "", err
	}
	newText, _ := base64.StdEncoding.DecodeString(text)
	if len(newText)%block.BlockSize() != 0 {
		return "", errors.New("无效的解密字符串")
	}

	blockMode := cipher.NewCBCDecrypter(block, newKey[:16])
	plainText := make([]byte, len(newText))
	blockMode.CryptBlocks(plainText, newText)
	plainText = PKCS7UnPadding(plainText)
	return string(plainText), nil
}
