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
	"strconv"

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

func (t Decrypter) Transform(r Transformer) (any, error) {
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
			fmt.Println("Skipping CryptoParams")
			continue
		}

		if !tags[fieldName].Enabled {
			tmp.FieldByName(fieldName).Set(fieldValue)
			continue
		}

		var decryptedValue reflect.Value
		if decryptedValue, err = t.decryptField(fieldType, fieldValue, tmp.FieldByName(fieldName).Kind(), cryptoConfig); err != nil {
			return nil, err
		}

		tmp.FieldByName(fieldName).Set(t.convertValue(decryptedValue.Bytes(), tmp.FieldByName(fieldName).Kind()))
	}

	outputValue.Set(tmp)
	return output, nil
}

func (t Decrypter) decryptField(fieldType reflect.Type, fieldValue reflect.Value, outputType reflect.Kind, cryptoConfig sio.Config) (reflect.Value, error) {
	var (
		err error
		out reflect.Value
	)
	if fieldType.Implements(reflect.TypeOf((*Transformer)(nil)).Elem()) {
		if out, err = t.decryptEmbeddedStruct(fieldValue, cryptoConfig); err != nil {
			return reflect.Value{}, err
		}
	} else {

		var source []byte
		source, err = hex.DecodeString(fieldValue.String())
		if err != nil {
			return reflect.Value{}, err
		}
		outBuf := make([]byte, 0)
		decryptedData := bytes.NewBuffer(outBuf)
		if _, err = sio.Decrypt(decryptedData, bytes.NewReader(source), cryptoConfig); err != nil {
			return reflect.Value{}, fmt.Errorf("failed to decrypt data: %w", err)
		}

		out = reflect.ValueOf(decryptedData)

	}

	return out, nil
}

func (t Decrypter) decryptEmbeddedStruct(field reflect.Value, cryptoConfig sio.Config) (reflect.Value, error) {
	var (
		err       error
		decrypter Decrypter
		output    any
	)

	decrypter = NewDecrypter(t.key, getEmbeddedTransformConfig(field))

	if output, err = decrypter.Transform(field.Interface().(Transformer)); err != nil {
		return reflect.Value{}, err
	}
	return reflect.ValueOf(output), nil
}

func (t Decrypter) convertValue(decryptedData []byte, kind reflect.Kind) reflect.Value {
	switch kind {
	case reflect.Int:
		byteToInt, _ := strconv.Atoi(string(decryptedData))
		return reflect.ValueOf(byteToInt)
	case reflect.String:
		return reflect.ValueOf(string(decryptedData))
	case reflect.Struct:
		return reflect.ValueOf(decryptedData)
	default:
		return reflect.ValueOf(decryptedData)
	}
}

func getCryptoParams(fieldValue reflect.Value) CryptoParams {
	return fieldValue.FieldByName("CryptoParams").Interface().(CryptoParams)
}
