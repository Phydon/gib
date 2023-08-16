# gib

turning text into **gibberish**

*quick file en-/decoding // en-/decrypting "on the fly"*


### Supported en-/decoding // en-/decrypting methods:

*work in progress*

* base64 (constant time)
* bytes
* caesar cipher
* hex
* l33t
* xor

## Usage

### Short Usage

```
Usage: gib [OPTIONS] [PATH] [COMMAND]

Commands:
  log, -L, --log  Show content of the log file
  help            Print this message or the help of the given subcommand(s)

Arguments:
  [PATH]  Add a path

Options:
  -c, --copy
          Create a copy of the file
  -d, --decode <DECODING/DECRYPTING METHOD>
          Decode/Decrypt the file
  -e, --encode <ENCODING/ENCRYPTING METHOD>
          Encode/Encrypt the file
  -3, --l33t <Mode>
          Set l33t mode [default: soft] [possible values: soft, hard]
  -l, --list
          List all available en-/decoding // en-/decrypting methods
  -p, --password
          Secure a file with a password
  -h, --help
          Print help (see more with '--help')
  -V, --version
          Print version
```


### Long Usage
```
Usage: gib [OPTIONS] [PATH] [COMMAND]

Commands:
  log, -L, --log  Show content of the log file
  help            Print this message or the help of the given subcommand(s)

Arguments:
  [PATH]
          Add a path

Options:
  -c, --copy
          Create a copy of the file in the config directory

  -d, --decode <DECODING/DECRYPTING METHOD>
          Decode/Decrypt the file

  -e, --encode <ENCODING/ENCRYPTING METHOD>
          Encode/Encrypt the file

  -3, --l33t <Mode>
          Set l33t mode

          [default: soft]
          [possible values: soft, hard]

  -l, --list
          List all available en-/decoding // en-/decrypting methods

  -p, --password
          Secure a file with a password

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
