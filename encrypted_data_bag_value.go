package chef

import (
  "bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type EncryptedDataBagValue struct {
	encryptedData []byte
	hmac          []byte
	iv            []byte
	version       int
	cipher        string
}

func NewEncryptedDataBagValue(encryptedValues interface{}) *EncryptedDataBagValue {
	if values, ok := encryptedValues.(map[string]interface{}); ok {
		obj := new(EncryptedDataBagValue)

		if v, ok := values["encryptedData"]; ok {
			obj.encryptedData = v.([]byte)
		}

		if v, ok := values["hmac"]; ok {
			obj.hmac = v.([]byte)
		}

		if v, ok := values["iv"]; ok {
			obj.iv = v.([]byte)
		}

		if v, ok := values["version"]; ok {
			obj.version = v.(int)
		}

		if v, ok := values["cipher"]; ok {
			obj.cipher = v.(string)
		}

		return obj
	}
	return nil
}

// DecryptValue returns a decrypted data bag value using version 2 implementation
func (obj *EncryptedDataBagValue) DecryptValue(secret []byte) (string, error) {
	err := obj.ValidateHmac(secret)
	if err != nil {
		return "", err
	}

	if obj.cipher != "aes-256-cbc" {
		return "", fmt.Errorf("Encryption algorithm is incorrect.")
	}

	encryptedDataBytes, err := base64.StdEncoding.DecodeString(string(obj.encryptedData))
	if err != nil {
		return "", err
	}

	ivBytes, err := base64.StdEncoding.DecodeString(string(obj.iv))
	if err != nil {
		return "", err
	}

	shaKey := sha256.Sum256(secret)
	block, err := aes.NewCipher(shaKey[:])
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(encryptedDataBytes, encryptedDataBytes)

  return obj.parseJSON(encryptedDataBytes)
}

func (obj *EncryptedDataBagValue) ValidateHmac(secret []byte) error {
	candidateHmacBytes, err := base64.StdEncoding.DecodeString(string(obj.hmac))
	if err != nil {
		return err
	}

	hmacHash := hmac.New(sha256.New, secret)
	hmacHash.Write(obj.encryptedData)
	expectedHmacBytes := hmacHash.Sum(nil)

	if !hmac.Equal(candidateHmacBytes, expectedHmacBytes) {
		return fmt.Errorf("Error decrypting data bag value: invalid hmac. Most likely the provided key is incorrect")
	}

	return nil
}

func (obj *EncryptedDataBagValue) parseJSON(byteSlice []byte) (string, error) {
  trimmedBytes := bytes.TrimRight(byteSlice, "\b")

  var resultJson map[string]string
  err := json.Unmarshal(trimmedBytes, &resultJson)
  if err != nil {
    return "", err
  }

  if result, ok := resultJson["json_wrapper"]; ok {
    return result, nil
  }

  return "", fmt.Errorf("Unable to parse result JSON")
}
