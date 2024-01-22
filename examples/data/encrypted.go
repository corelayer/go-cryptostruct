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

package data

import "github.com/corelayer/go-cryptostruct/pkg/cryptostruct"

type SecureSecondEmbeddedData struct {
	Age          int                       `json:"age" yaml:"age" mapstructure:"age" secure:"false"`
	CryptoParams cryptostruct.CryptoParams `json:"cryptoParams" yaml:"cryptoParams" mapstructure:"cryptoParams"`
}

func (d SecureSecondEmbeddedData) GetTransformConfig() cryptostruct.TransformConfig {
	return cryptostruct.TransformConfig{
		Decrypted: SecondEmbeddedData{},
		Encrypted: SecureSecondEmbeddedData{},
	}
}

type SecureEmbeddedData struct {
	FirstName    string                    `json:"firstName" yaml:"firstName" mapstructure:"firstName" secure:"true"`
	LastName     string                    `json:"lastName" yaml:"lastName" mapstructure:"lastName" secure:"true"`
	Details      SecondEmbeddedData        `json:"details" yaml:"details" mapstructure:"details" secure:"false"`
	CryptoParams cryptostruct.CryptoParams `json:"cryptoParams" yaml:"cryptoParams" mapstructure:"cryptoParams"`
}

func (d SecureEmbeddedData) GetTransformConfig() cryptostruct.TransformConfig {
	return cryptostruct.TransformConfig{
		Decrypted: EmbeddedData{},
		Encrypted: SecureEmbeddedData{},
	}
}

func (d SecureEmbeddedData) GetCryptoParams() cryptostruct.CryptoParams {
	return d.CryptoParams
}

type SecureData struct {
	Name         string                    `json:"name" yaml:"name" mapstructure:"name" secure:"true"`
	Title        string                    `json:"title" yaml:"title" mapstructure:"title" secure:"true"`
	Count        string                    `json:"count" yaml:"count" mapstructure:"count" secure:"true"`
	Details      SecureEmbeddedData        `json:"details" yaml:"details" mapstructure:"details" secure:"true"`
	SliceDetails []SecureEmbeddedData      `json:"sliceDetails" yaml:"sliceDetails" mapstructure:"sliceDetails" secure:"true"`
	NumberSlice  []string                  `json:"numberSlice" yaml:"numberSlice" mapstructure:"numberSlice" secure:"true"`
	CryptoParams cryptostruct.CryptoParams `json:"cryptoParams" yaml:"cryptoParams" mapstructure:"cryptoParams"`
}

func (d SecureData) GetTransformConfig() cryptostruct.TransformConfig {
	return cryptostruct.TransformConfig{
		Decrypted: InsecureData{},
		Encrypted: SecureData{},
	}
}

func (d SecureData) GetCryptoParams() cryptostruct.CryptoParams {
	return d.CryptoParams
}
