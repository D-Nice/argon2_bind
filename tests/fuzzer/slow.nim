import
  argon2_bind,
  strutils,
  terminal

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
    tCost = 2
    mCost = 1 shl 12
    pCost = 2
    hLen  = 64

  const a2Params =
    Argon2Params(
      timeCost: tCost,
      memoryCostK: mCost,
      parallelism: pCost,
      hashLen: hLen,
      algoType: Argon2i,
      version: Argon2Version13
    )

  discard pass.getOutput(
    salt,
    a2Params,
  )

main()
