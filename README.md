# argon2_bind

Nim binding library to the Argon2 C implementation.

<!-- vim-markdown-toc GFM -->

* [Requirements](#requirements)
  * [Alpine Linux](#alpine-linux)
* [Docs](#docs)
* [Notes](#notes)

<!-- vim-markdown-toc -->

## Requirements

* libargon2

### Alpine Linux

`apk add --no-cache argon2-libs`

to statically compile, get the development variant available for your OS

`apk add --no-cache argon2-dev`

or compile the C code and utilize libargon2.a yourself.

## Docs

Available @ <https://d-nice.github.io/argon2_bind/>

## Notes

This library by default dynamically links to libargon2 on your system.
You can still statically link by having the development libargon2 variant
and passing the appropriate parameters to your project:

`nim c --dynlibOverride:libargon2 -L:/usr/lib/libargon2.a myproject.nim`

With `myproject.nim` referring to your own project importing this library,
and you having to provide your own path to `libargon2.a` via the `-L` flag

Tested on Linux only, namely on the Alpine Linux docker image, use it
for turnkey access to fuzzing etc...

You will need at least 1 GiB of free memory to run the tests.
