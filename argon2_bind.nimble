# Package
version       = "0.1.0"
author        = "D-Nice"
description   = "Bindings for the reference Argon2 C lib"
license       = "Apache-2.0"
srcDir        = "src"

# Dependencies
requires "nim >= 1.0.0"

when defined(nimdistros):
  import distros
  if detectOs(Ubuntu) or detectOs(Debian):
    foreignDep "libargon2-dev"
  elif detectOs(Alpine):
    foreignDep "argon2-dev"
  else:
    foreignDep "libargon2"

import
  sugar,
  sequtils,
  strutils

func srcPaths: seq[string] =
  const dirs =
    @[
      "src/"
    ]
  for dir in dirs:
    result.add(dir.listFiles.filter(x => x[dir.len .. x.high].endsWith(".nim")))

func testPaths: seq[string] =
  const dir = "tests/"
  return dir.listFiles.filter(x =>
    x[dir.len .. x.high].startsWith('t') and
    x.endsWith(".nim")
  )

# Nimscript Tasks

## docs
task docs, "Deploy doc html + search index to public/ directory":
  let
    deployDir = projectDir() & "/public/"
    genDocCmd = "nim doc --out:$1 --index:on $2" % [deployDir, srcPaths()[0]]
    genTheIndexCmd = "nim buildIndex -o:$1/theindex.html $1" % [deployDir]
    deployJsFile = deployDir & "dochack.js"
    docHackJsSource = "https://nim-lang.github.io/Nim/dochack.js" # devel docs dochack.js
  mkDir deployDir
  exec genDocCmd
  exec genTheIndexCmd
  when defined Linux:
    exec "ln -sf " & srcPaths()[0][4 .. ^4] & "html public/index.html"
  if not fileExists deployJsFile:
    withDir deployDir:
      exec "curl -LO " & docHackJsSource

## checks
const checkCmd = "nim c -cf -w:on --hints:off -o:/dev/null --styleCheck:"
task check_src, "Compile src with all checks on":
  for src in srcPaths():
    exec checkCmd & "error " & src
task check_tests, "Compile tests with all checks on":
  for test in testPaths():
    exec checkCmd & "error " & test
task check_all, "Compile check everything and run tests":
  exec "nimble check_src && nimble check_tests"

## fuzzing (for alpine nim image)
task fuzz_fast, "Runs afl on getOutput":
  exec "export AFL_HARDEN=1; nim c --dynlibOverride:libargon2 -L:/usr/lib/libargon2.a -f -o:/tmp/nim/argon2_full/fuzz_fast tests/fuzzer/fast.nim && afl-fuzz -i tests/fuzzer/in-fuzz -o tests/fuzzer/out-fuzz_fast /tmp/nim/argon2_full/fuzz_fast"
task fuzz_fast_more, "Runs afl on getOutput":
  exec "export AFL_HARDEN=1; nim c --dynlibOverride:libargon2 -L:/usr/lib/libargon2.a -f -o:/tmp/nim/argon2_full/fuzz_fast_more tests/fuzzer/fast_more.nim && afl-fuzz -i tests/fuzzer/in-fuzz -o tests/fuzzer/out-fuzz_fast_more /tmp/nim/argon2_full/fuzz_fast_more"
task fuzz_slow, "Runs afl on getOutput":
  exec "export AFL_HARDEN=1; nim c --dynlibOverride:libargon2 -L:/usr/lib/libargon2.a -f -o:/tmp/nim/argon2_full/fuzz_slow tests/fuzzer/slow.nim && afl-fuzz -i tests/fuzzer/in-fuzz -o tests/fuzzer/out-fuzz_slow /tmp/nim/argon2_full/fuzz_slow"
task fuzz_slow_more, "Runs afl on getOutput":
  exec "export AFL_HARDEN=1; nim c --dynlibOverride:libargon2 -L:/usr/lib/libargon2.a -f -o:/tmp/nim/argon2_full/fuzz_slow_more tests/fuzzer/slow_more.nim && afl-fuzz -i tests/fuzzer/in-fuzz -o tests/fuzzer/out-fuzz_slow_more /tmp/nim/argon2_full/fuzz_slow_more"

## dependency installer
task install_deps, "Installs dependencies for supported systems":
  when defined(Linux):
    const distro = staticExec("cat /etc/os-release | grep ^ID_LIKE= || cat /etc/os-release | grep ^ID=")
    case distro.split('=', 1)[1]:
      of "alpine":
        exec "apk add --no-cache argon2-dev"
      of "debian":
        exec "apt install -y libargon2-dev"
      else:
        echo "Unknown Linux distro... install libargon2-dev or the appropriate argon2 development files for your distro manually!"
  else:
    echo "Unsupported OS"
task install_fuzz, "Installs dependencies including those for fuzzing":
  when defined(Linux):
    const distro = staticExec("cat /etc/os-release | grep ^ID_LIKE= || cat /etc/os-release | grep ^ID=")
    case distro.split('=', 1)[1]:
      of "alpine":
        exec "apk add --no-cache afl"
      of "debian":
        exec "apt install -y afl || echo AFL unavailable: fuzzing tasks unusuable"
  exec "nimble install_deps"
task i, "Installs dependencies for supported systems":
  exec "nimble install_deps"

