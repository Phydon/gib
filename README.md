# gib

turning text into **gibberish**

*quick file en-/decoding // en-/decrypting "on the fly"*


### Supported en-/decoding // en-/decrypting methods:

*work in progress*

* base64 (constant time)
* caesar cipher
* hex


## Usage

### Short Usage

```
GIB
Leann Phydon <leann.phydon@gmail.com>

Encode / Decode files

Usage: gib [OPTIONS] [PATH] [COMMAND]

Commands:
  log, -L, --log  Show content of the log file
  help            Print this message or the help of the given subcommand(s)

Arguments:
  [PATH]  Add a path

Options:
  -d, --decode <Decoding method>  Decode the file
  -e, --encode <Encoding method>  Encode the file
  -l, --list                      List all available encoding / decoding methods
  -h, --help                      Print help (see more with '--help')
  -V, --version                   Print version
```


### Long Usage
```
GIB
Leann Phydon <leann.phydon@gmail.com>

GIBBERISH
Quickly encode / decode files 'on the fly'

Usage: gib [OPTIONS] [PATH] [COMMAND]

Commands:
  log, -L, --log  Show content of the log file
  help            Print this message or the help of the given subcommand(s)

Arguments:
  [PATH]
          Add a path

Options:
  -d, --decode <Decoding method>
          Decode the file

  -e, --encode <Encoding method>
          Encode the file

  -l, --list
          List all available encoding / decoding methods

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```


## Installation

### Windows

via Cargo or get the ![binary](https://github.com/Phydon/gib/releases)


## WARNING

**always backup your files before using this program**

**this is not a very secure way of encrypting your files**
