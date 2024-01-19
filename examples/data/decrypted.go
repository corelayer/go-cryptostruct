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

type SecondEmbeddedData struct {
	Age int `json:"age" yaml:"age" mapstructure:"age" secure:"false"`
}

func (d SecondEmbeddedData) GetTransformConfig() cryptostruct.TransformConfig {
	return cryptostruct.TransformConfig{
		Decrypted: SecondEmbeddedData{},
		Encrypted: SecureSecondEmbeddedData{},
	}
}

type EmbeddedData struct {
	FirstName string             `json:"firstName" yaml:"firstName" mapstructure:"firstName" secure:"true"`
	LastName  string             `json:"lastName" yaml:"lastName" mapstructure:"lastName" secure:"true"`
	Details   SecondEmbeddedData `json:"details" yaml:"details" mapstructure:"details" secure:"false"`
}

func (d EmbeddedData) GetTransformConfig() cryptostruct.TransformConfig {
	return cryptostruct.TransformConfig{
		Decrypted: EmbeddedData{},
		Encrypted: SecureEmbeddedData{},
	}
}

type InsecureData struct {
	Name    string       `json:"name" yaml:"name" mapstructure:"name" secure:"true"`
	Count   int          `json:"count" yaml:"count" mapstructure:"count" secure:"true"`
	Details EmbeddedData `json:"details" yaml:"details" mapstructure:"details" secure:"true"`
}

func (d InsecureData) GetTransformConfig() cryptostruct.TransformConfig {
	return cryptostruct.TransformConfig{
		Decrypted: InsecureData{},
		Encrypted: SecureData{},
	}
}
