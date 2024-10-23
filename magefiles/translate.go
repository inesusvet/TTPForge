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

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/facebookincubator/ttpforge/pkg/args"
	"gopkg.in/yaml.v3"
)

type AtomicSchema struct {
	AttackTechnique string       `yaml:"attack_technique"`
	DisplayName     string       `yaml:"display_name"`
	AtomicTests     []AtomicTest `yaml:"atomic_tests"`
}

// TTP represents the top-level structure for a TTP
// (Tactics, Techniques, and Procedures) object.
// TODO: Replace with existing TTP struct
type TTP struct {
	Name        string
	Description string            `yaml:"description,omitempty"`
	Environment map[string]string `yaml:"env,omitempty,flow"`
	Args        []args.Spec       `yaml:"args,omitempty"`
	Mitre       Mitre
	Steps       []Step
	// Omit WorkDir, but expose for testing.
	WorkDir string `yaml:"-"`
}

type AtomicTest struct {
	Name               string             `yaml:"name"`
	Description        string             `yaml:"description,omitempty"`
	SupportedPlatforms []string           `yaml:"supported_platforms,omitempty"`
	Executor           AtomicTestExecutor `yaml:"executor"`
	Dependencies       []Dependency
	// TODO: Ignore it completely?
	DependencyExecutorName string                   `yaml:"dependency_executor_name"`
	InputArguments         map[string]InputArgument `yaml:"input_arguments,omitempty,flow"`
}

type AtomicTestExecutor struct {
	// TODO: Use existing Executor Enum
	Name           string `yaml:"name,omitempty"`
	Command        string
	CleanupCommand string `yaml:"cleanup_command"`
}

type InputArgument struct {
	Description string
	Type        string
	Default     interface{}
}

type Dependency struct {
	Description      string
	PrereqCommand    string `yaml:"prereq_command"`
	GetPrereqCommand string `yaml:"get_prereq_command"`
}

type Mitre struct {
	Tactics       []string `yaml:"tactics,omitempty"`
	Techniques    []string `yaml:"techniques,omitempty"`
	Subtechniques []string `yaml:"subtechniques,omitempty"`
}

type MitreTechniqueInfo struct {
	FullName        string `json:"full_name"`
	TacticFullNames string `json:"tactic_full_name"`
}

type MitreMap struct {
	Map map[string]MitreTechniqueInfo `json:"techniques"`
}

type Step struct {
	Name     string        `yaml:"name"`
	Inline   string        `yaml:"inline,omitempty"`
	Executor string        `yaml:"executor,omitempty"`
	Cleanup  CleanupAction `yaml:"cleanup,omitempty"`
}

type CleanupAction struct {
	Inline string
}

type ArgumentSpec struct {
	Name        string `yaml:"name"`
	Type        string `yaml:"type,omitempty"`
	Default     string `yaml:"default,omitempty"`
	Description string `yaml:"description,omitempty"`
}

func ConvertSchema(atomic AtomicSchema) []TTP {
	result := make([]TTP, len(atomic.AtomicTests))

	for i, test := range atomic.AtomicTests {
		ttp := TTP{
			Name:        test.Name,
			Description: test.Description,
			Mitre: Mitre{
				Techniques:    []string{atomic.AttackTechnique},
				Tactics:       []string{},
				Subtechniques: []string{},
			},
		}

		// Populate Args for each step from the test's InputArguments
		argumentReplacements := make(map[string]string, len(test.InputArguments))
		for argName, inputArg := range test.InputArguments {
			spec := args.Spec{
				Name:    argName,
				Type:    inputArg.Type,
				Default: fmt.Sprintf("%v", inputArg.Default), // convert interface{} to string
				// TODO: bump ttpforge dependency to support description field
				// Description: inputArg.Description,
			}
			ttp.Args = append(ttp.Args, spec)
			argPlaceholder := fmt.Sprintf("#{%s}", argName) // TODO: consider spaces
			argumentReplacements[argPlaceholder] = fmt.Sprintf("{{.Args.%v}}", argName)
		}

		step := Step{
			Name:     formatStepName(test.Name),
			Inline:   replaceArgumentPlaceholders(test.Executor.Command, argumentReplacements),
			Executor: test.Executor.Name,
			Cleanup: CleanupAction{
				Inline: replaceArgumentPlaceholders(test.Executor.CleanupCommand, argumentReplacements),
			},
		}
		ttp.Steps = append(ttp.Steps, step)

		result[i] = ttp
	}

	return result
}

// copyDir copies a whole directory recursively
func copyDir(src string, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Generate new destination path
		relativePath, _ := filepath.Rel(src, path)
		destPath := filepath.Join(dst, relativePath)

		if info.IsDir() {
			// Create a new directory
			return os.MkdirAll(destPath, info.Mode())
		}

		// Copy the file
		fileData, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destPath, fileData, info.Mode())
	})
}

// formatStepName formats the given step name by converting it to lowercase
// and replacing spaces with dashes.
func formatStepName(name string) string {
	// Convert to lowercase
	name = strings.ToLower(name)

	// Replace spaces with dashes
	name = strings.ReplaceAll(name, " ", "-")

	// Additional cleanup can be added if needed

	return name
}

func replaceArgumentPlaceholders(inline string, replacements map[string]string) string {
	for old, new := range replacements {
		inline = strings.ReplaceAll(inline, old, new)
	}
	return inline
}

// Loads local JSON file with all known Mitre tags to build a map from Technique ID to Tactic IDs
func NewMitreMap(filename string) (*MitreMap, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	mitreMap := MitreMap{
		Map: make(map[string]MitreTechniqueInfo),
	}
	err = json.Unmarshal(data, &mitreMap)
	if err != nil {
		return nil, err
	}

	return &mitreMap, nil
}

// ConvertYAMLSchema reads from a provided TTP path, converts its schema, and writes the result to the specified output path
func ConvertYAMLSchema(ttpPath string) error {
	if ttpPath == "" {
		return fmt.Errorf("a valid TTP path must be provided")
	}

	// Read the original YAML file following the naming convention
	originalYAMLPath := filepath.Join(ttpPath, filepath.Base(ttpPath)+".yaml")
	data, err := os.ReadFile(originalYAMLPath)
	if err != nil {
		return err
	}

	var atomic AtomicSchema
	err = yaml.Unmarshal(data, &atomic)
	if err != nil {
		return err
	}

	targetTtpList := ConvertSchema(atomic)

	// Load Mitre TTP map
	// TODO: figure out why the map is empty
	mitreMap, err := NewMitreMap("magefiles/ttp_map.json")
	if err != nil {
		return err
	}
	fmt.Printf("Build Mitre map: %+v\n", mitreMap)

	// Populating Mitre Tactics
	for _, ttp := range targetTtpList {
		fmt.Printf("Processing TTP %s: %s\n", ttp.Name, ttp.Mitre.Techniques)
		if len(ttp.Mitre.Techniques) != 1 {
			continue
		}
		key := ttp.Mitre.Techniques[0]
		info, ok := mitreMap.Map[key]
		if ok {
			fmt.Printf("Found info for %s: %+v\n", key, info)
			ttp.Mitre.Tactics = strings.Split(info.TacticFullNames, ", ")
			ttp.Mitre.Techniques = []string{info.FullName}
		}
	}

	// Write to the specified output path
	outputDir := ttpPath

	// Ensure the directory exists
	err = os.MkdirAll(outputDir, os.ModePerm)
	if err != nil {
		return err
	}

	// Convert to YAML files all tests
	for _, target := range targetTtpList {
		result, err := yaml.Marshal(&target)
		if err != nil {
			return err
		}
		outputFilePath := filepath.Join(outputDir, fmt.Sprintf("%v.yaml", target.Name))

		err = os.WriteFile(outputFilePath, result, os.ModePerm)
		if err != nil {
			return err
		}

		// Check if "src" directory exists in the original location and copy it to the destination if it does
		srcPath := filepath.Join(ttpPath, "src")
		_, err = os.Stat(srcPath)
		if err == nil {
			// Directory exists, copy it
			destSrcPath := filepath.Join(outputDir, "src")
			err = copyDir(srcPath, destSrcPath)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
