/*
 * Copyright 2023 CoreLayer BV
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
package main

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"time"

	"github.com/corelayer/go-cryptostruct/examples/data"
	"github.com/corelayer/go-cryptostruct/pkg/cryptostruct"
)

func main() {
	var (
		err error
		p   cryptostruct.CryptoParams
		tc  cryptostruct.TransformConfig
		sd  any
	)
	fmt.Println("ENCRYPTING DATA")
	fmt.Println("_______________")

	id := data.InsecureData{
		Name:  "insecuredata",
		Count: 100,
		Details: data.EmbeddedData{
			FirstName: "First",
			LastName:  "Last",
		},
	}
	fmt.Println(id)

	tc = id.GetTransformConfig()

	p, err = cryptostruct.NewCryptoParams("AES_256_GCM", "")
	if err != nil {
		panic(err)
	}
	masterKey := hex.EncodeToString([]byte("masterKey"))
	encrypter := cryptostruct.NewEncrypter(masterKey, p, tc)

	sd, err = encrypter.Transform(id)
	if err != nil {
		panic(err)
	}
	fmt.Println(sd, reflect.TypeOf(sd))
	fmt.Println("_________________")

	time.Sleep(2 * time.Second)
	fmt.Println("")
	fmt.Println("DECRYPTING CONFIG")
	fmt.Println("_________________")

	decryptdata := sd.(data.SecureData)
	decrypter := cryptostruct.NewDecrypter(masterKey, decryptdata.GetTransformConfig())
	newid, err2 := decrypter.Transform(decryptdata)
	if err2 != nil {
		panic(err2)
	}
	fmt.Println(newid, reflect.TypeOf(newid))
	fmt.Println("_________________")
}
