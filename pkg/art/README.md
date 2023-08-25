# TTPForge/art

The `art` package is a part of the TTPForge.

---

## Table of contents

- [Functions](#functions)
- [Installation](#installation)
- [Usage](#usage)
- [Tests](#tests)
- [Contributing](#contributing)
- [License](#license)

---

## Functions

### Ability.EncodeCommand()

```go
EncodeCommand()
```

EncodeCommand encodes the command of an Ability using base64 encoding.

**Parameters:**

a: A pointer to the Ability structure.

---

### Atomic.GenerateArtVarsAndAbilities()

```go
GenerateArtVarsAndAbilities()
```

GenerateArtVarsAndAbilities generates the ArtInputVars and ArtAbilities for an Atomic structure.

**Parameters:**

a: A pointer to the Atomic structure.

---

### Atomic.LoadArtYAML(string)

```go
LoadArtYAML(string) error
```

LoadArtYAML loads the ART YAML from a given path into the Atomic structure.

**Parameters:**

path: Path to the ART YAML file.

**Returns:**

error: An error if any issue occurs while loading the ART YAML.

---

### Atomic.LoadAtomic(string)

```go
LoadAtomic(string) error
```

LoadAtomic loads a JSON file into the Atomic structure.

**Parameters:**

path: Path to the JSON file.

**Returns:**

error: An error if any issue occurs while loading the JSON into Atomic.

---

### Config.Load(string)

```go
Load(string) error
```

Load reads a YAML file and loads it into the Config structure.

**Parameters:**

path: Path to the YAML file.

**Returns:**

error: An error if any issue occurs while loading the YAML into Config.

---

### NewAbility(int64, string)

```go
NewAbility(int64, string) *Ability
```

NewAbility initializes a new Ability and encodes its command.

**Parameters:**

id: Identifier for the new ability.
command: The command for the new ability.

**Returns:**

*Ability: A pointer to the newly created Ability.

---

### NewAtomic()

```go
NewAtomic() *Atomic
```

NewAtomic initializes a new Atomic structure.

**Returns:**

*Atomic: A pointer to the newly created Atomic structure.

---

### NewConfig(string)

```go
NewConfig(string) *Config, error
```

NewConfig initializes a new Config.

**Parameters:**

path: Path to the configuration file.

**Returns:**

*Config: A pointer to the newly created Config.
error: An error if any issue occurs while initializing the Config.

---

### NewVar(int64, string)

```go
NewVar(int64, string) *Var
```

NewVar initializes a new Var and encodes its value.

**Parameters:**

id: Identifier for the ability the variable belongs to.
name: Name of the variable.
value: Value of the variable.

**Returns:**

*Var: A pointer to the newly created Var.

---

### Var.EncodeValue()

```go
EncodeValue()
```

EncodeValue encodes the value of the Var structure.

**Parameters:**

v: A pointer to the Var structure.

---

## Installation

To use the TTPForge/art package, you first need to install it.
Follow the steps below to install via go get.

```bash
go get github.com/facebookincubator/ttpforge/art
```

---

## Usage

After installation, you can import the package in your Go project
using the following import statement:

```go
import "github.com/facebookincubator/ttpforge/art"
```

---

## Tests

To ensure the package is working correctly, run the following
command to execute the tests for `TTPForge/art`:

```bash
go test -v
```

---

## Contributing

Pull requests are welcome. For major changes,
please open an issue first to discuss what
you would like to change.

---

## License

This project is licensed under the MIT
License - see the [LICENSE](https://github.com/facebookincubator/TTPForge/blob/main/LICENSE)
file for details.
