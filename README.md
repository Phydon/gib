# gib

turning text into **gibberish**

*quick file en-/decoding // en-/decrypting "on the fly"*


### Supported en-/decoding // en-/decrypting methods:

*work in progress*

* base64 (constant time)
* caesar cipher
* chacha20poly1305
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
  -k, --key
          Use a specific key for encoding
  -3, --l33t <Mode>
          Set l33t mode [default: soft] [possible values: soft, hard]
  -l, --list
          List all available en-/decoding // en-/decrypting methods
  -s, --sign
          Verify a file with a signature
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

  -k, --key
          Use a specific key for encoding
          If the encoding method allows a custom key, you will get prompted to enter a key
          To decode this file again correctly, the same key must be used
          This flag gets ignored if the encoding method doesn`t allow a specific key
          This is NOT a password

  -3, --l33t <Mode>
          Set l33t mode

          [default: soft]
          [possible values: soft, hard]

  -l, --list
          List all available en-/decoding // en-/decrypting methods

  -s, --sign
          Verify a file with a signature

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
