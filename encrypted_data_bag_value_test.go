package chef

import (
  "bytes"
	"testing"
)

func TestNewEncryptedDataBagValue(t *testing.T) {
  encryptedValues := testFixture()
  obj := NewEncryptedDataBagValue(encryptedValues)

	if !bytes.Equal(encryptedValues["encryptedData"].([]byte), obj.encryptedData) {
		t.Error("encryptedData field not correctly set in struct")
	}

  if !bytes.Equal(encryptedValues["hmac"].([]byte), obj.hmac) {
		t.Error("hmac field not correctly set in struct")
	}

  if !bytes.Equal(encryptedValues["iv"].([]byte), obj.iv) {
		t.Error("iv field not correctly set in struct")
	}

  if encryptedValues["version"].(int) != obj.version {
		t.Error("version field not correctly set in struct")
	}

  if encryptedValues["cipher"].(string) != obj.cipher {
		t.Error("cipher field not correctly set in struct")
	}
}

func TestNewEncryptedDataBagValue_nil(t *testing.T) {
  obj := NewEncryptedDataBagValue("blah")
  if obj != nil {
    t.Error("Invalid argument to constructor should return nil")
  }
}

func TestValidateHmac(t *testing.T) {
	obj := NewEncryptedDataBagValue(testFixture())

  // Should be good
  err := obj.ValidateHmac(testSecret())
  if err != nil {
    t.Error(err)
  }

  // Should be invalid
  err = obj.ValidateHmac([]byte("wrong_secret"))
  if err == nil {
    t.Error("ValidateHmac should not succeed with incorrect secret")
  }
}

func TestDecryptValue(t *testing.T) {
  obj := NewEncryptedDataBagValue(testFixture())

  val, err := obj.DecryptValue(testSecret())
  if err != nil {
    t.Error(err)
  }

  if val != testVal() {
    t.Errorf("Got value: %v, expected value: %v\n", val, testVal())
  }
}

// Helper functions

func testFixture() map[string]interface{} {
  return map[string]interface{}{
		"encryptedData": []byte("AKyDsX/eiYImvjJljM8By3zi6fR7ekqhqEY1sPSOYK0=\n"),
		"hmac":          []byte("CDtQRHLtY1ohbnH27BEm6hxskEsj/lLa45SHHZHoABQ=\n"),
		"iv":            []byte("4tDhUVRqApUlKC11q5gA5A==\n"),
		"version":       2,
		"cipher":        "aes-256-cbc",
	}
}

func testSecret() []byte {
  return []byte("abcdef1234")
}

func testKey() string {
  return "hello"
}

func testVal() string {
  return "world"
}
