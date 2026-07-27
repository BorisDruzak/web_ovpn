package helper

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"unicode/utf8"
)

const (
	maxDocumentBytes = 1 << 20
	maxStringRunes   = 256
	maxArrayItems    = 16
	maxNestingDepth  = 16
	maxObjectFields  = 64
	maxResultBytes   = 4096
)

func parseStrictJSON(raw []byte) (any, error) {
	if len(raw) == 0 || len(raw) > maxDocumentBytes {
		return nil, contractError("json_limit_exceeded", "JSON document has invalid size")
	}
	if !utf8.Valid(raw) {
		return nil, contractError("json_invalid_utf8", "JSON document is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeStrictValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, contractError("json_invalid", "JSON document has trailing data")
	}
	return value, nil
}

func decodeStrictValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxNestingDepth {
		return nil, contractError("json_limit_exceeded", "JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, contractError("json_invalid", "JSON document is malformed")
	}
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, contractError("json_invalid", "JSON object is malformed")
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, contractError("json_invalid", "JSON object key is invalid")
				}
				if utf8.RuneCountInString(key) > maxStringRunes {
					return nil, contractError("json_limit_exceeded", "JSON object key is too long")
				}
				if _, exists := object[key]; exists {
					return nil, contractError("json_duplicate_key", "JSON object contains a duplicate key")
				}
				if len(object) >= maxObjectFields {
					return nil, contractError("json_limit_exceeded", "JSON object has too many fields")
				}
				value, err := decodeStrictValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
				return nil, contractError("json_invalid", "JSON object is not closed")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				if len(array) >= maxArrayItems {
					return nil, contractError("json_limit_exceeded", "JSON array has too many values")
				}
				value, err := decodeStrictValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
				return nil, contractError("json_invalid", "JSON array is not closed")
			}
			return array, nil
		default:
			return nil, contractError("json_invalid", "JSON delimiter is invalid")
		}
	case json.Number:
		text := typed.String()
		if !isCanonicalIntegerToken(text) {
			return nil, contractError("json_non_integer", "JSON numbers must be base-10 integers")
		}
		value, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return nil, contractError("json_number_out_of_range", "JSON integer is out of range")
		}
		return value, nil
	case string:
		if utf8.RuneCountInString(typed) > maxStringRunes {
			return nil, contractError("json_limit_exceeded", "JSON string is too long")
		}
		return typed, nil
	case bool:
		return typed, nil
	case nil:
		return nil, nil
	default:
		return nil, contractError("json_invalid", "JSON value is invalid")
	}
}

func isCanonicalIntegerToken(value string) bool {
	if value == "0" {
		return true
	}
	start := 0
	if len(value) > 0 && value[0] == '-' {
		start = 1
	}
	if start >= len(value) || value[start] < '1' || value[start] > '9' {
		return false
	}
	for index := start + 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func canonicalJSON(value any) ([]byte, error) {
	output := make([]byte, 0, 1024)
	output, err := appendCanonicalJSON(output, value)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func appendCanonicalJSON(output []byte, value any) ([]byte, error) {
	switch typed := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		output = append(output, '{')
		for index, key := range keys {
			if index > 0 {
				output = append(output, ',')
			}
			output = appendASCIIJSONString(output, key)
			output = append(output, ':')
			var err error
			output, err = appendCanonicalJSON(output, typed[key])
			if err != nil {
				return nil, err
			}
		}
		return append(output, '}'), nil
	case []any:
		output = append(output, '[')
		for index, item := range typed {
			if index > 0 {
				output = append(output, ',')
			}
			var err error
			output, err = appendCanonicalJSON(output, item)
			if err != nil {
				return nil, err
			}
		}
		return append(output, ']'), nil
	case string:
		return appendASCIIJSONString(output, typed), nil
	case int64:
		return strconv.AppendInt(output, typed, 10), nil
	case bool:
		return strconv.AppendBool(output, typed), nil
	case nil:
		return append(output, "null"...), nil
	default:
		return nil, fmt.Errorf("unsupported canonical JSON type %T", value)
	}
}

func appendASCIIJSONString(output []byte, value string) []byte {
	const hexadecimal = "0123456789abcdef"
	output = append(output, '"')
	for _, character := range value {
		switch character {
		case '"', '\\':
			output = append(output, '\\', byte(character))
		case '\b':
			output = append(output, `\b`...)
		case '\f':
			output = append(output, `\f`...)
		case '\n':
			output = append(output, `\n`...)
		case '\r':
			output = append(output, `\r`...)
		case '\t':
			output = append(output, `\t`...)
		default:
			if character < 0x20 || character >= 0x7f {
				if character <= 0xffff {
					output = appendUnicodeEscape(output, uint16(character), hexadecimal)
				} else {
					codepoint := character - 0x10000
					output = appendUnicodeEscape(output, uint16(0xd800+(codepoint>>10)), hexadecimal)
					output = appendUnicodeEscape(output, uint16(0xdc00+(codepoint&0x3ff)), hexadecimal)
				}
			} else {
				output = append(output, byte(character))
			}
		}
	}
	return append(output, '"')
}

func appendUnicodeEscape(output []byte, value uint16, hexadecimal string) []byte {
	return append(output, '\\', 'u',
		hexadecimal[(value>>12)&0xf],
		hexadecimal[(value>>8)&0xf],
		hexadecimal[(value>>4)&0xf],
		hexadecimal[value&0xf],
	)
}

func objectValue(value any, name string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, contractError(name+"_type_invalid", name+" must be an object")
	}
	return object, nil
}

func requireFields(object map[string]any, expected []string, prefix string) error {
	expectedSet := make(map[string]struct{}, len(expected))
	for _, field := range expected {
		expectedSet[field] = struct{}{}
		if _, exists := object[field]; !exists {
			return contractError(prefix+"_missing_field", prefix+" has missing fields")
		}
	}
	for field := range object {
		if _, exists := expectedSet[field]; !exists {
			return contractError(prefix+"_unknown_field", prefix+" has unknown fields")
		}
	}
	return nil
}

func stringValue(value any, prefix string) (string, error) {
	text, ok := value.(string)
	if !ok {
		return "", contractError(prefix+"_type_invalid", prefix+" must be a string")
	}
	if text == "" {
		return "", contractError(prefix+"_value_invalid", prefix+" must not be empty")
	}
	return text, nil
}

func optionalStringValue(value any, prefix string) (*string, error) {
	if value == nil {
		return nil, nil
	}
	text, err := stringValue(value, prefix)
	if err != nil {
		return nil, err
	}
	return &text, nil
}

func positiveIntegerValue(value any, prefix string) (int64, error) {
	number, ok := value.(int64)
	if !ok {
		return 0, contractError(prefix+"_type_invalid", prefix+" must be an integer")
	}
	if number <= 0 {
		return 0, contractError(prefix+"_value_invalid", prefix+" must be positive")
	}
	return number, nil
}

func boolValue(value any, prefix string) (bool, error) {
	boolean, ok := value.(bool)
	if !ok {
		return false, contractError(prefix+"_type_invalid", prefix+" must be a boolean")
	}
	return boolean, nil
}

func arrayValue(value any, prefix string) ([]any, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, contractError(prefix+"_type_invalid", prefix+" must be an array")
	}
	return array, nil
}
