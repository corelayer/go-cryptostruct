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

func NewDecrypter(masterKeyHex string, c TransformConfig) Decrypter {
	return Decrypter{
		key: masterKeyHex,
		// params: p,
		config: c,
	}
}

type Decrypter struct {
	key string
	// params CryptoParams
	config TransformConfig
}

func (t Decrypter) Transform(r DecryptTransformer) (any, error) {
	var (
		err          error
		tags         map[string]Tag
		output       any
		cryptoConfig sio.Config
	)

	// Get input type and value of r
	inputType := reflect.TypeOf(r)
	inputValue := reflect.ValueOf(r)

	// // Get CryptoParams from input
	// cryptoParams = r.GetCryptoParams()
	cryptoConfig, err = r.GetCryptoParams().GetCryptoConfig(t.key)
	if err != nil {
		return nil, fmt.Errorf("could not initialize crypto parameters: %w", err)
	}

	// Get the struct tags for r
	tags, err = getTags(r)
	if err != nil {
		return nil, fmt.Errorf("could not get tags: %w", err)
	}

	// Get struct to which data must be converted
	output = t.config.Decrypted
	//
	// outputType := reflect.TypeOf(output)
	// fmt.Println("outputType", outputType)

	// To be able to set the fields for the output, we need to get the Value of the output pointer
	outputValue := reflect.ValueOf(&output).Elem()
	// To be able to mutate the outputValue, we must first get a temporary outputValue
	tmp := reflect.New(outputValue.Elem().Type()).Elem()
	tmp.Set(outputValue.Elem())

	// Process all fields in r
	for i := 0; i < inputValue.NumField(); i++ {
		fieldName := inputType.Field(i).Name
		fieldType := inputType.Field(i).Type
		fieldValue := inputValue.Field(i)

		// CryptoParams must not be stored in the output
		if fieldType == reflect.TypeOf(CryptoParams{}) {
			continue
		}

		// If field tag is not enabled, copy the value to the output
		if !tags[fieldName].Enabled {
			tmp.FieldByName(fieldName).Set(fieldValue)
			continue
		}

		// Decrypt current field
		var decryptedValue reflect.Value
		switch inputValue.Field(i).Kind() {
		case reflect.Slice:
			if decryptedValue, err = t.decryptSlice(fieldValue, tmp.FieldByName(fieldName).Type(), cryptoConfig); err != nil {
				return nil, err
			}
		default:
			if decryptedValue, err = t.decryptFields(fieldType, fieldValue, tmp.FieldByName(fieldName).Kind(), cryptoConfig); err != nil {
				return nil, err
			}
		}
		tmp.FieldByName(fieldName).Set(decryptedValue)
	}

	outputValue.Set(tmp)
	return output, nil
}

func (t Decrypter) decryptSlice(inputValue reflect.Value, outputType reflect.Type, cryptoConfig sio.Config) (reflect.Value, error) {
	var (
		err    error
		output reflect.Value
	)
	// Create a slice of the outputType with the correct capacity
	output = reflect.MakeSlice(outputType, 0, 0)

	// Loop over the input slice and encrypt each element
	for i := 0; i < inputValue.Len(); i++ {
		var decryptedValue reflect.Value
		if decryptedValue, err = t.decryptFields(reflect.TypeOf(inputValue.Index(i).Interface()), inputValue.Index(i), outputType.Elem().Kind(), cryptoConfig); err != nil {
			return reflect.Value{}, err
		}
		// Append the decrypted value to the output
		output = reflect.Append(output, decryptedValue)
	}
	return output, nil
}

func (t Decrypter) decryptFields(fieldType reflect.Type, fieldValue reflect.Value, outputKind reflect.Kind, cryptoConfig sio.Config) (reflect.Value, error) {
	var (
		err error
		out reflect.Value
	)

	// Check if the fieldType implements interface DecryptTransformer
	if fieldType.Implements(reflect.TypeOf((*DecryptTransformer)(nil)).Elem()) {
		if out, err = t.decryptStruct(fieldValue); err != nil {
			return reflect.Value{}, err
		}
	} else {
		// Decode fieldValue from hex encoded string to []byte
		var source []byte
		source, err = hex.DecodeString(fieldValue.String())
		if err != nil {
			return reflect.Value{}, err
		}

		encryptedDataReader := bytes.NewReader(source)
		decryptedDataWriter := bytes.NewBuffer(make([]byte, 0))

		// Decrypt data in encryptedDataReader into decryptedDataWriter using cryptoconfig
		if _, err = sio.Decrypt(decryptedDataWriter, encryptedDataReader, cryptoConfig); err != nil {
			return reflect.Value{}, fmt.Errorf("failed to decrypt data: %w", err)
		}

		// Convert decrypted data from hex string to desired output type
		out, err = convertHexStringToValue(decryptedDataWriter.String(), outputKind)
		if err != nil {
			return reflect.Value{}, err
		}
	}
	return out, nil
}

func (t Decrypter) decryptStruct(field reflect.Value) (reflect.Value, error) {
	var (
		err       error
		decrypter Decrypter
		output    any
	)

	decrypter = NewDecrypter(t.key, getEmbeddedTransformConfig(field))

	if output, err = decrypter.Transform(field.Interface().(DecryptTransformer)); err != nil {
		return reflect.Value{}, err
	}
	return reflect.ValueOf(output), nil
}
