package py

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Object is a JSON object that remembers key order, like a Python dict. Files that users keep in git (such as
// .om/config.json) must come back with their keys where they were, or every om write is a noisy diff.
// Values are *Object, []any, string, json.Number, bool or nil.
type Object struct {
	keys []string
	m    map[string]any
}

// NewObject returns an empty Object.
func NewObject() *Object { return &Object{m: map[string]any{}} }

// Get returns the value of k.
func (o *Object) Get(k string) (any, bool) { v, ok := o.m[k]; return v, ok }

// Set sets k, keeping its position if it exists and appending it otherwise.
func (o *Object) Set(k string, v any) {
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

// Delete removes k.
func (o *Object) Delete(k string) {
	if _, ok := o.m[k]; !ok {
		return
	}
	delete(o.m, k)
	for i, x := range o.keys {
		if x == k {
			o.keys = append(o.keys[:i], o.keys[i+1:]...)
			break
		}
	}
}

// Keys returns the keys in order.
func (o *Object) Keys() []string { return append([]string(nil), o.keys...) }

// Len is the number of keys.
func (o *Object) Len() int { return len(o.keys) }

// ParseObject decodes a JSON document whose top level is an object. A duplicate key keeps its first position and
// its last value, as Python's json does.
func ParseObject(data []byte) (*Object, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	o, ok := v.(*Object)
	if !ok {
		return nil, fmt.Errorf("not a JSON object")
	}
	return o, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil // string, json.Number, bool, nil
	}
	switch d {
	case '{':
		o := NewObject()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			o.Set(kt.(string), v)
		}
		_, err := dec.Token()
		return o, err
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token()
		return arr, err
	}
	return nil, fmt.Errorf("unexpected %v", d)
}

// Dumps is json.dumps(v, indent=2) byte for byte for the supported values (ensure_ascii, ", " free separators
// with newlines, ": " after keys, "{}" and "[]" for empty containers). Plain maps are written with sorted keys;
// use Object for insertion order.
func Dumps(v any) string {
	var b strings.Builder
	dump(&b, v, 0)
	return b.String()
}

func dump(b *strings.Builder, v any, depth int) {
	pad := strings.Repeat("  ", depth+1)
	end := strings.Repeat("  ", depth)
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		b.WriteString(JSONString(x))
	case json.Number:
		b.WriteString(x.String())
	case int:
		b.WriteString(strconv.Itoa(x))
	case int64:
		b.WriteString(strconv.FormatInt(x, 10))
	case float64:
		b.WriteString(FloatRepr(x))
	case []string:
		a := make([]any, len(x))
		for i, s := range x {
			a[i] = s
		}
		dump(b, a, depth)
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return
		}
		b.WriteString("[\n")
		for i, e := range x {
			b.WriteString(pad)
			dump(b, e, depth+1)
			if i < len(x)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(end + "]")
	case map[string]any:
		o := NewObject()
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			o.Set(k, x[k])
		}
		dump(b, o, depth)
	case *Object:
		if x.Len() == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteString("{\n")
		for i, k := range x.keys {
			b.WriteString(pad + JSONString(k) + ": ")
			dump(b, x.m[k], depth+1)
			if i < len(x.keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(end + "}")
	default:
		panic(fmt.Sprintf("py.Dumps: unsupported %T", v))
	}
}

// DumpsCompact is json.dumps(v, sort_keys=True) with Python's default separators ", " and ": " on one line.
// Maps are written with sorted keys; Object keeps insertion order.
func DumpsCompact(v any) string {
	var b strings.Builder
	dumpCompact(&b, v)
	return b.String()
}

func dumpCompact(b *strings.Builder, v any) {
	switch x := v.(type) {
	case []string:
		a := make([]any, len(x))
		for i, s := range x {
			a[i] = s
		}
		dumpCompact(b, a)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			dumpCompact(b, e)
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(JSONString(k) + ": ")
			dumpCompact(b, x[k])
		}
		b.WriteByte('}')
	case *Object:
		b.WriteByte('{')
		for i, k := range x.keys {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(JSONString(k) + ": ")
			dumpCompact(b, x.m[k])
		}
		b.WriteByte('}')
	default:
		dump(b, v, 0) // scalars print the same either way
	}
}
