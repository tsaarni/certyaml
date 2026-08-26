// Copyright certyaml authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/tsaarni/certyaml/internal/manifest"
)

// printFieldReference prints the certs.yaml field reference from jsonschema struct tags.
func printFieldReference(w io.Writer) {
	fmt.Fprintln(w, "DESCRIPTION:")
	fmt.Fprintln(w, "    Each YAML document (separated by '---') defines one certificate.")
	fmt.Fprintln(w, "    The subject field must be unique across the manifest.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "FIELDS:")
	printStructFields(w, reflect.TypeOf(manifest.CertificateManifest{}))
}

func printStructFields(w io.Writer, t reflect.Type) {
	for i := range t.NumField() {
		field := t.Field(i)

		if field.Anonymous {
			printStructFields(w, field.Type)
			continue
		}

		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}

		tag := field.Tag.Get("jsonschema")
		if tag == "" {
			continue
		}

		attrs := parseTagAttrs(tag)
		typeName := typeName(field.Type)

		suffix := ""
		if _, ok := attrs["required"]; ok {
			suffix = " -required-"
		}

		fmt.Fprintf(w, "  %s\t<%s>%s\n", name, typeName, suffix)
		if v := attrs["description"]; v != "" {
			fmt.Fprintf(w, "    %s\n", v)
		}
		if v := attrs["enum"]; v != "" {
			fmt.Fprintf(w, "    Valid values: %s\n", v)
		}
		if v := attrs["default"]; v != "" {
			fmt.Fprintf(w, "    Default: %s\n", v)
		}
		if v := attrs["example"]; v != "" {
			fmt.Fprintf(w, "    Example: %s\n", v)
		}
		fmt.Fprintln(w)
	}
}

// typeName returns a human-readable type name for display.
func typeName(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Slice:
		return "[]" + typeName(t.Elem())
	case reflect.Pointer:
		return typeName(t.Elem())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return "integer"
	case reflect.Bool:
		return "boolean"
	default:
		return "string"
	}
}

// parseTagAttrs parses "key=val,key=val" into a map.
func parseTagAttrs(tag string) map[string]string {
	attrs := make(map[string]string)
	for _, part := range strings.Split(tag, ",") {
		k, v, _ := strings.Cut(part, "=")
		if prev, exists := attrs[k]; exists {
			attrs[k] = prev + ", " + v // Repeated keys are comma-joined.
		} else {
			attrs[k] = v
		}
	}
	return attrs
}
