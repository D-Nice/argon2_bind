# argon2_bind

Nim binding library to the Argon2 [C implementation](https://github.com/P-H-C/phc-winner-argon2).

<!-- vim-markdown-toc GFM -->

* [Dependencies](#dependencies)
  * [Static Linking (default)](#static-linking-default)
  * [Dynamic Linking](#dynamic-linking)
    * [Supported Distros](#supported-distros)
* [Docs](#docs)
* [Notes](#notes)
  * [Multithreading](#multithreading)

<!-- vim-markdown-toc -->

## Dependencies

### Static Linking (default)

* requires `--threads:on` flag when compiling

### Dynamic Linking

* libargon2
* pass `-d:dynlink` flag when compiling to trigger dynamic argon2 use

#### Supported Distros

`nimble i`

To install any package dependencies.

## Docs

Available @ <https://d-nice.github.io/argon2_bind/argon2_bind.html>

## Notes

You will need at least 1 GiB of free memory to run the tests.

### Multithreading

The argon2 execution will be multithreaded in all instances, except if
using `--dynlibOverride:libargon2 -d:dynlink`, even if you pass `--threads:on`.
However, it doesn't make much sense to pass these parameters though, with the
static linking being built-in as the default.
