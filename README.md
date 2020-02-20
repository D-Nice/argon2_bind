# argon2_bind

[![nimble](https://raw.githubusercontent.com/yglukhov/nimble-tag/master/nimble.png)](https://nimble.directory/pkg/argon2_bind)

[![builder-linux](https://github.com/D-Nice/argon2_bind/workflows/builder-linux/badge.svg)](https://github.com/D-Nice/argon2_bind/actions?query=workflow%3Abuilder-linux+branch%3Amaster)
[![builder-win](https://github.com/D-Nice/argon2_bind/workflows/builder-win/badge.svg)](https://github.com/D-Nice/argon2_bind/actions?query=workflow%3Abuilder-win+branch%3Amaster)
[![builder-macos](https://github.com/D-Nice/argon2_bind/workflows/builder-macos/badge.svg)](https://github.com/D-Nice/argon2_bind/actions?query=workflow%3Abuilder-macos+branch%3Amaster)
[![tester](https://github.com/D-Nice/argon2_bind/workflows/tester/badge.svg)](https://github.com/D-Nice/argon2_bind/actions?query=workflow%3Atester+branch%3Amaster)
[![linter](https://github.com/D-Nice/argon2_bind/workflows/linter/badge.svg)](https://github.com/D-Nice/argon2_bind/actions?query=workflow%3Alinter+branch%3Amaster)

[![GitHub deployments](https://img.shields.io/github/deployments/d-nice/argon2_bind/github-pages?label=docs&style=flat)](https://github.com/D-Nice/argon2_bind/deployments?environment=github-pages#activity-log)
[![GitHub file size in bytes](https://img.shields.io/github/size/D-Nice/argon2_bind/src/argon2_bind.nim?style=flat)](https://github.com/D-Nice/argon2_bind/blob/master/src/argon2_bind.nim)
[![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/d-nice/argon2_bind?label=version&style=flat)](https://github.com/D-Nice/argon2_bind/releases)

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
