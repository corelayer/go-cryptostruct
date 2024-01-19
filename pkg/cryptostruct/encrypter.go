/*
 * Copyright 2024 CoreLayer BV
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package cryptostruct

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"

	"github.com/minio/sio"
)

func NewEncrypter(masterKeyHex string, p CryptoParams, c TransformConfig) Encrypter {
	return Encrypter{
		key:    masterKeyHex,
		params: p,
		config: c,
	}
}

type Encrypter struct {
	key    string
	params CryptoParams
	config TransformConfig
}

func (t Encrypter) Transform(r any) (any, error) {
	var (
		err    error
		tags   map[string]Tag
		output any
	)

	// Get input type and value of r
	inputType := reflect.TypeOf(r)
	inputValue := reflect.ValueOf(r)

	// Get the struct tags for r
	tags, err = getTags(r)
	if err != nil {
		return nil, err
	}

	// Get struct to which data must be converted
	output = t.config.Encrypted

	// To be able to set the fields for the output, we need to get the Value of the output pointer
	outputValue := reflect.ValueOf(&output).Elem()
	// To be able to mutate the outputValue, we must first get a temporary outputValue
	tmp := reflect.New(outputValue.Elem().Type()).Elem()
	tmp.Set(outputValue.Elem())

	// Store the encryption parameters for the output
	tmp.FieldByName("CryptoParams").Set(reflect.ValueOf(t.params))

	// Process all fields in r
	for i := 0; i < inputValue.NumField(); i++ {
		fieldName := inputType.Field(i).Name
		fieldType := inputType.Field(i).Type
		fieldValue := inputValue.Field(i)

		// If the field must not be encrypted, store the input value into the output value
		// Input and Output field type MUST be the same!!!
		if !tags[fieldName].Enabled {
			tmp.FieldByName(fieldName).Set(fieldValue)
			continue
		}

		var encryptedValue reflect.Value
		switch inputValue.Field(i).Kind() {
		case reflect.Slice:
			if encryptedValue, err = t.encryptSlice(fieldValue, tmp.FieldByName(fieldName).Type()); err != nil {
				return nil, err
			}
		default:
			if encryptedValue, err = t.encryptFields(fieldType, fieldValue); err != nil {
				return nil, err
			}
		}
		tmp.FieldByName(fieldName).Set(encryptedValue)
	}

	outputValue.Set(tmp)
	return output, nil
}

func (t Encrypter) encryptSlice(inputValue reflect.Value, outputType reflect.Type) (reflect.Value, error) {
	var (
		err    error
		output reflect.Value
	)

	// Create a slice of the outputType with the correct capacity
	output = reflect.MakeSlice(outputType, 0, 0)

	// Loop over the input slice and encrypt each element
	for i := 0; i < inputValue.Len(); i++ {
		var encryptedValue reflect.Value
		if encryptedValue, err = t.encryptFields(reflect.TypeOf(inputValue.Index(i).Interface()), inputValue.Index(i)); err != nil {
			return reflect.Value{}, err
		}
		// Append the encrypted value to the output
		output = reflect.Append(output, encryptedValue)
	}
	return output, nil
}

func (t Encrypter) encryptFields(fieldType reflect.Type, fieldValue reflect.Value) (reflect.Value, error) {
	var (
		err          error
		cryptoConfig sio.Config
		out          reflect.Value
	)
	fmt.Println("encrypt field", fieldType, fieldValue)
	// Generate sio.Config from CryptoParams
	cryptoConfig, err = t.params.GetCryptoConfig(t.key)
	if err != nil {
		return reflect.Value{}, fmt.Errorf("could not initialize crypto parameters: %w", err)
	}

	// Check if the current field is a struct, which implements the interface EncryptTransformer
	// Decide to encrypt the field or the embedded struct
	if fieldType.Implements(reflect.TypeOf((*EncryptTransformer)(nil)).Elem()) {
		if out, err = t.encryptStruct(fieldValue, t.params.CipherSuite); err != nil {
			return reflect.Value{}, err
		}
	} else {
		fmt.Println(fieldValue.Kind(), fieldType)
		source := []byte(fieldValue.String())
		outBuf := make([]byte, 0)
		encryptedData := bytes.NewBuffer(outBuf)
		if _, err = sio.Encrypt(encryptedData, bytes.NewReader(source), cryptoConfig); err != nil {
			return reflect.Value{}, fmt.Errorf("failed to encrypt data: %w", err)
		}
		out = reflect.ValueOf(hex.EncodeToString(encryptedData.Bytes()))
	}
	return out, nil
}

func (t Encrypter) encryptStruct(field reflect.Value, cipherSuite string) (reflect.Value, error) {
	var (
		err          error
		encrypter    Encrypter
		cryptoParams CryptoParams
		output       any
	)

	cryptoParams, err = NewCryptoParams(cipherSuite)
	if err != nil {
		return reflect.Value{}, err
	}
	encrypter = NewEncrypter(t.key, cryptoParams, getEmbeddedTransformConfig(field))

	if output, err = encrypter.Transform(field.Interface()); err != nil {
		return reflect.Value{}, err
	}

	return reflect.ValueOf(output), nil

}
