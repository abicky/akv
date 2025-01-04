# akv

[![main](https://github.com/abicky/akv/actions/workflows/main.yaml/badge.svg)](https://github.com/abicky/akv/actions/workflows/main.yaml)

`akv` is a CLI tool for injecting Azure Key Vault secrets.
For example, `inject` subcommand injects secrets into input data as follows:

```console
$ az keyvault secret set --vault-name example --name password --value 'C@6LWQnuKDjQYHNE'
$ echo 'password: akv://example/password' | akv inject
password: C@6LWQnuKDjQYHNE
```

As you can see, `akv://example/password` in the input, which is the secret reference in the format `akv://<vault-name>/<secret-name>`, has been replaced with the secret.

## Installation

### Install pre-compiled binary

Download the binary archive from the [releases page](https://github.com/abicky/akv/releases), unpack it, and move the executable "akv" to a directory in your path (e.g. `/usr/local/bin`).

For example, you can install the latest binary on a Mac with Apple silicon by running the following commands:

```sh
curl -LO https://github.com/abicky/akv/releases/latest/download/akv_darwin_arm64.tar.gz
tar xvf akv_darwin_arm64.tar.gz
mv akv_darwin_arm64/akv /usr/local/bin/
```

If you download the archive via a browser on macOS Catalina or later, you may receive the message "“akv” cannot be opened because the developer cannot be verified."
In such a case, you need to delete the attribute "com.apple.quarantine" as follows:

```sh
xattr -d com.apple.quarantine /path/to/akv
```

### Install using Homebrew (macOS or Linux)

```sh
brew install abicky/tools/akv
```

### Install from source

```sh
go install github.com/abicky/akv@latest
```

or

```sh
git clone https://github.com/abicky/akv
cd akv
make install
```

### Enable completions

The `completion` subcommand generates an autocompletion script. For example, you can generate the autocompletion script for zsh as follows:

```sh
akv completion zsh > /usr/local/share/zsh/site-functions/_akv
```

If you install using Homebrew, Homebrew will generate autocompletion scripts.


## Usage

### inject subcommand

```console
$ akv inject --help
This command injects Azure Key Vault secrets into input data
with secret references in the format "akv://<vault-name>/<secret-name>"

Usage:
  akv inject [flags]

Examples:
  $ az keyvault secret set --vault-name example --name password --value 'C@6LWQnuKDjQYHNE'
  $ echo 'password: akv://example/password' | akv inject
  password: C@6LWQnuKDjQYHNE
  $ az keyvault secret set --vault-name example --name multiline-secret --file <(echo -n "Hello\nworld")
  $ echo 'secret: akv://example/multiline-secret' | akv inject --quote
  secret: "Hello\nworld"
  $ echo '{"secret": "akv://example/multiline-secret"}' | akv inject --escape
  {"secret": "Hello\nworld"}
  $ cat secret.yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: password
  stringData:
    password: akv://example/password
    secret: akv://example/multiline-secret
  $ akv inject --quote < secret.yaml
  apiVersion: v1
  kind: Secret
  metadata:
    name: password
  stringData:
    password: "C@6LWQnuKDjQYHNE"
    secret: "Hello\u000aworld"

Flags:
      --escape   Escape special characters in secrets
  -h, --help     help for inject
      --quote    Escape and enclose each secret in double quotes
```

### exec subcommand

```console
$ akv exec --help
This command executes a command with Azure Key Vault secrets injected into environment
variables whose value is a secret reference in the format "akv://<vault-name>/<secret-name>"

Usage:
  akv exec [flags] -- COMMAND [args...]

Examples:
  $ az keyvault secret set --vault-name example --name password --value 'C@6LWQnuKDjQYHNE'
  $ env PASSWORD=akv://example/password akv exec -- printenv PASSWORD
  C@6LWQnuKDjQYHNE

Flags:
  -h, --help   help for exec
```

## Author

Takeshi Arabiki ([@abicky](https://github.com/abicky))
