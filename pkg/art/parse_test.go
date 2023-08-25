/*
Copyright © 2023-present, Meta Platforms, Inc. and affiliates
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

package art_test

import (
	"encoding/base64"
	"testing"

	"github.com/facebookincubator/ttpforge/pkg/art"
)

func TestNewConfig(t *testing.T) {
	// This test assumes you have an actual YAML file. If you don't, this will fail.
	tests := []struct {
		name     string
		input    string
		expected art.Config
		hasError bool
	}{
		{
			name:     "Valid path",
			input:    "path_to_valid_yaml.yaml",
			expected: art.Config{ArtPath: "some_path", CtiPath: "another_path"},
			hasError: false,
		},
		{
			name:     "Invalid path",
			input:    "invalid_path.yaml",
			expected: art.Config{},
			hasError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := art.NewConfig(tc.input)
			if (err != nil) != tc.hasError {
				t.Fatalf("expected error status %v; got %v", tc.hasError, (err != nil))
			}
			if *cfg != tc.expected {
				t.Fatalf("expected config %v; got %v", tc.expected, cfg)
			}
		})
	}
}

func TestLoadArtYAML(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect *art.Atomic
		err    error
	}{
		// TODO: Add test cases here
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			atomic := art.NewAtomic()
			err := atomic.LoadArtYAML(tc.path)
			if err != tc.err {
				t.Errorf("Expected error %v, but got %v", tc.err, err)
			}
			// Add more assertions
		})
	}
}

func TestNewAbility(t *testing.T) {
	tests := []struct {
		name     string
		id       int64
		command  string
		expected *art.Ability
	}{
		{
			name:    "base64 encoding",
			id:      1,
			command: "ls",
			expected: &art.Ability{
				AbilityID: 1,
				Command:   base64.StdEncoding.EncodeToString([]byte("ls")),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ab := art.NewAbility(tc.id, tc.command)
			if *ab != *tc.expected {
				t.Fatalf("expected %v; got %v", tc.expected, ab)
			}
		})
	}
}

func TestNewVar(t *testing.T) {
	tests := []struct {
		name     string
		id       int64
		varName  string
		value    string
		expected *art.Var
	}{
		{
			name:    "base64 encoding",
			id:      1,
			varName: "VAR1",
			value:   "value1",
			expected: &art.Var{
				AbilityID: 1,
				VarName:   "VAR1",
				Value:     base64.StdEncoding.EncodeToString([]byte("value1")),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := art.NewVar(tc.id, tc.varName, tc.value)
			if *v != *tc.expected {
				t.Fatalf("expected %v; got %v", tc.expected, v)
			}
		})
	}
}
