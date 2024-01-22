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
	"reflect"
)

type Tag struct {
	Enabled bool
}

func getTags(r any) (map[string]Tag, error) {
	var err error

	// r := *new(i)
	t := reflect.TypeOf(r)

	// Create a map with capacity of the number of fields in T
	var m = make(map[string]Tag, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		fieldName := t.Field(i).Name

		// Check if secure tag is set on field
		tag, ok := t.Field(i).Tag.Lookup("secure")
		if !ok {
			continue
		}
		m[fieldName] = parseTag(tag)
	}

	return m, err
}

func parseTag(t string) Tag {
	var tag Tag
	switch t {
	case "true":
		tag = Tag{Enabled: true}
	default:
		tag = Tag{Enabled: false}
	}
	return tag
}
