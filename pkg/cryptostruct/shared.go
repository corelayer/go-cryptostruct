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
	"encoding/binary"
	"encoding/hex"
	"reflect"
)

func getEmbeddedTransformConfig(field reflect.Value) TransformConfig {
	fnConfig := field.MethodByName("GetTransformConfig")
	fnOutput := fnConfig.Call([]reflect.Value{})
	return fnOutput[0].Interface().(TransformConfig)
}

func convertValueToHexString(v reflect.Value) (string, error) {
	var (
		err error
	)
	switch v.Kind() {
	case reflect.Int:
		buf := make([]byte, 0)
		bufWriter := bytes.NewBuffer(buf)
		err = binary.Write(bufWriter, binary.BigEndian, v.Int())
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(bufWriter.Bytes()), nil
	default:
		return hex.EncodeToString([]byte(v.String())), nil
	}
}

func convertHexStringToValue(input string, outputKind reflect.Kind) (reflect.Value, error) {
	var (
		err     error
		decoded []byte
	)
	// Decode hex encoded string to []byte
	decoded, err = hex.DecodeString(input)
	if err != nil {
		return reflect.Value{}, err
	}

	// Create reflect.Value based on the output reflect.Kind
	switch outputKind {
	case reflect.Int:
		decodedInt := binary.BigEndian.Uint64(decoded)
		return reflect.ValueOf(int(decodedInt)), nil
	default:
		return reflect.ValueOf(string(decoded)), nil
	}
}
