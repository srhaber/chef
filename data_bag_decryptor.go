package chef

import (
	_ "fmt"
)

type DataBagDecryptor struct {
	item   map[string]interface{}
	secret []byte
}

func (d *DataBagDecryptor) DecryptItem() (DataBagItem, error) {
	item := map[string]string{
		"id": d.item["id"].(string),
	}

	for key, encryptedValue := range d.item {
		if key == "id" {
			continue
		}

		v := NewEncryptedDataBagValue(encryptedValue)

		decryptedValue, err := v.DecryptValue(d.secret)
		if err != nil {
			return nil, err
		}

		item[key] = decryptedValue
	}

	return item, nil
}
