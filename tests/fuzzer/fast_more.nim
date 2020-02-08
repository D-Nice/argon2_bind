import
  argon2_bind,
  strutils,
  terminal

# This fuzzer runs through most of the functions

template clearEOL(s: string) =
  s.removeSuffix("\n")
  s.removeSuffix("\r")

proc main(): void =
  var input = newStringOfCap(128)
  var pass = newStringOfCap(64)
  var salt = newStringOfCap(64)
  
  if stdin.isatty:
    quit 1

  input = stdin.readAll
  # rm EOL chars LF or CR
  input.clearEOL

  let args = input.split("\n", 1)
  if (args.len <= 1):
    quit 1
  pass = args[0]
  salt = args[1]

  const 
    tCost = 1
    mCost = 8
    pCost = 1
    hLen  = 32

  const a2Params = @[
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2i,
      version: Argon2Version13
    ),
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2d,
      version: Argon2Version13
    ),
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2id,
      version: Argon2Version13
    ),
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2i,
      version: Argon2Version10
    ),
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2d,
      version: Argon2Version10
    ),
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2id,
      version: Argon2Version10
    ),
  ]

  for param in a2Params:
    {.unroll.}
    discard pass.getOutput(
      salt,
      param,
    )

    discard pass.getRawHash(
      salt,
      param,
    )

    let enc = pass.getEncodedHash(
      salt,
      param,
    )

    discard enc.isVerified(pass)

main()
