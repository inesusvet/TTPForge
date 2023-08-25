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

package art

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the configuration details for ART.
//
// **Attributes:**
//
// ArtPath: Path to ART files.
// CtiPath: Path to CTI files.
type Config struct {
	ArtPath string `yaml:"art_path"`
	CtiPath string `yaml:"cti_path"`
}

// Ability represents the details of an ability.
//
// **Attributes:**
//
// AbilityID: Identifier for the ability.
// Command: The command to be executed for this ability.
type Ability struct {
	AbilityID int64
	Command   string
}

// Var represents a variable tied to an ability.
//
// **Attributes:**
//
// AbilityID: Identifier for the ability the variable belongs to.
// VarName: Name of the variable.
// Value: Value of the variable.
type Var struct {
	AbilityID int64
	VarName   string
	Value     string
}

// Atomic represents the structure of an atomic test.
//
// **Attributes:**
//
// AbilityID: Identifier for the atomic test.
// Platform: Platform on which the atomic test runs.
// Executor: Executor name.
// Command: The command to be executed.
// InputArguments: Arguments passed to the atomic test.
// Encoder: List of encoders used.
// ArtAbilities: List of art abilities tied to this atomic.
// ArtInputVars: List of variables tied to this atomic.
type Atomic struct {
	AbilityID      int64  `json:"ability_id"`
	Platform       string `json:"platform"`
	Executor       string `json:"executor"`
	Command        string `json:"command"`
	InputArguments map[string]Argument
	Encoder        []string `json:"encoder"`
	ArtAbilities   []*Ability
	ArtInputVars   []*Var
}

// Argument represents the input arguments for an atomic test.
//
// **Attributes:**
//
// ID: Identifier for the argument.
// Name: Name of the argument.
// Default: Default value for the argument.
type Argument struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Default string `json:"default"`
}

// AtomicRedTeamYAML represents the structure of an ART TTP.
//
// **Attributes:**
//
// AttackTechnique: The attack technique.
// AtomicTests: List of atomic tests.
type AtomicRedTeamYAML struct {
	AttackTechnique string       `yaml:"attack_technique"`
	AtomicTests     []AtomicTest `yaml:"atomic_tests"`
}

// AtomicTest represents an atomic test in ART YAML.
//
// **Attributes:**
//
// Name: Name of the atomic test.
// SupportedPlatforms: List of platforms this test supports.
// InputArguments: Input arguments for the atomic test.
// Executor: Executor for the atomic test.
type AtomicTest struct {
	Name               string              `yaml:"name"`
	SupportedPlatforms []string            `yaml:"supported_platforms"`
	InputArguments     map[string]InputArg `yaml:"input_arguments"`
	Executor           Executor            `yaml:"executor"`
}

// Executor represents the executor details for an atomic test.
//
// **Attributes:**
//
// Name: Name of the executor.
// Command: Command associated with the executor.
type Executor struct {
	Name    string `yaml:"name"`
	Command string `yaml:"command"`
}

// InputArg represents an input argument in an AtomicTest.
//
// **Attributes:**
//
// Default: Default value for the input argument.
type InputArg struct {
	Default string `yaml:"default"`
}

// Helper function to process character replacements
func replaceSpecialChars(str string) string {
	// Replacing "\x07" with "a" for specific reasons (you can elaborate based on real reasons).
	str = strings.ReplaceAll(str, "\x07", "a")
	// Replacing "\\\\" with "\\" to correct potential escape sequence errors.
	str = strings.ReplaceAll(str, "\\\\", "\\")
	return str
}

// ProcessAtomicTest processes an individual Atomic Test from the
// provided AtomicTest structure, filters supported platforms, and
// creates abilities and variables from the atomic test.
//
// **Parameters:**
//
// atomicTest: The AtomicTest structure containing details of
// the test like supported platforms, executor commands, etc.
func (a *Atomic) ProcessAtomicTest(atomicTest AtomicTest) {
	for _, platform := range atomicTest.SupportedPlatforms {
		platform = strings.ToLower(platform)
		if platform != "windows" && platform != "linux" && platform != "macos" {
			continue
		}
		command := replaceSpecialChars(atomicTest.Executor.Command)

		artAbility := NewAbility(a.AbilityID, command)
		a.ArtAbilities = append(a.ArtAbilities, artAbility)

		for varName, varVal := range atomicTest.InputArguments {
			value := replaceSpecialChars(varVal.Default)
			artVar := NewVar(a.AbilityID, varName, value)
			a.ArtInputVars = append(a.ArtInputVars, artVar)
		}
	}
}

// NewConfig initializes a new Config.
//
// **Parameters:**
//
// path: Path to the configuration file.
//
// **Returns:**
//
// *Config: A pointer to the newly created Config.
// error: An error if any issue occurs while initializing the Config.
func NewConfig(path string) (*Config, error) {
	cfg := &Config{}
	err := cfg.LoadArtYAML(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadArtYAML reads an ART YAML file and loads it into the Config structure.
//
// **Parameters:**
//
// path: Path to the YAML file.
//
// **Returns:**
//
// error: An error if any issue occurs while loading the YAML into Config.
func (c *Config) LoadArtYAML(path string) error {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return err
	}

	return nil
}

// NewAbility initializes a new Ability and encodes its command.
//
// **Parameters:**
//
// id: Identifier for the new ability.
// command: The command for the new ability.
//
// **Returns:**
//
// *Ability: A pointer to the newly created Ability.
func NewAbility(id int64, command string) *Ability {
	ab := &Ability{
		AbilityID: id,
		Command:   command,
	}
	ab.EncodeCommand()
	return ab
}

// EncodeCommand encodes the command of an Ability using base64 encoding.
//
// **Parameters:**
//
// a: A pointer to the Ability structure.
func (a *Ability) EncodeCommand() {
	a.Command = base64.StdEncoding.EncodeToString([]byte(a.Command))
}

// NewVar initializes a new Var and encodes its value.
//
// **Parameters:**
//
// id: Identifier for the ability the variable belongs to.
// name: Name of the variable.
// value: Value of the variable.
//
// **Returns:**
//
// *Var: A pointer to the newly created Var.
func NewVar(id int64, name, value string) *Var {
	v := &Var{
		AbilityID: id,
		VarName:   name,
		Value:     value,
	}
	v.EncodeValue()
	return v
}

// EncodeValue encodes the value of the Var structure.
//
// **Parameters:**
//
// v: A pointer to the Var structure.
func (v *Var) EncodeValue() {
	v.Value = base64.StdEncoding.EncodeToString([]byte(v.Value))
}

// NewAtomic initializes a new Atomic structure.
//
// **Returns:**
//
// *Atomic: A pointer to the newly created Atomic structure.
func NewAtomic() *Atomic {
	return &Atomic{
		InputArguments: make(map[string]Argument),
		ArtAbilities:   make([]*Ability, 0),
		ArtInputVars:   make([]*Var, 0),
	}
}

// LoadAtomic loads a JSON file into the Atomic structure.
//
// **Parameters:**
//
// path: Path to the JSON file.
//
// **Returns:**
//
// error: An error if any issue occurs while loading the JSON into Atomic.
func (a *Atomic) LoadAtomic(path string) error {
	jsonFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	err = json.Unmarshal(jsonFile, a)
	if err != nil {
		return err
	}

	return nil
}

// GenerateArtVarsAndAbilities generates the ArtInputVars and ArtAbilities for an Atomic structure.
//
// **Parameters:**
//
// a: A pointer to the Atomic structure.
func (a *Atomic) GenerateArtVarsAndAbilities() {
	for varName, varVal := range a.InputArguments {
		value := replaceSpecialChars(varVal.Default)
		artVar := NewVar(a.AbilityID, varName, value)
		a.ArtInputVars = append(a.ArtInputVars, artVar)
	}

	a.ArtAbilities = append(a.ArtAbilities, NewAbility(a.AbilityID, a.Command))
}
