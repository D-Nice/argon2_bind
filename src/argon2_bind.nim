when defined(Linux):
  const libargon2 = "libargon2.so(|.1)"
elif defined(Windows):
  const libargon2 = "libargon2.dll"

type
  Argon2Error* = object of CatchableError

type
  Argon2Type* = enum
    Argon2d,
    Argon2i,
    Argon2id,

type
  Argon2Version* = enum
    Argon2Version10 = 0x10,
    Argon2Version13 = 0x13,

type
  Argon2Params* {.bycopy.} = object
    timeCost*, memoryCostK*, parallelism*, hashLen*: uint32
    algoType*: Argon2Type
    version*: Argon2Version


# By wrapping potential outputs in this object
# we are more easily able to pass nil as a parameter in nim
# in which case the C library will understand not to
# provide said output
type
  Argon2Output* = object
    hash*: seq[byte]
    encoded*: string

## INTERNAL TYPES
type
  ReturnCode = cint

const Argon2CurrentVersion* = Argon2Version13

const defaultParams = Argon2Params(
  timeCost: 3,
  memoryCostK: 4096,
  parallelism: 1,
  hashLen: 32,
  algoType: Argon2i,
  version: Argon2CurrentVersion
)

func setupArgon2Params*(
  timeCost: uint32 = defaultParams.timeCost,
  memoryCostK: uint32 = defaultParams.memoryCostK,
  parallelism: uint32 = defaultParams.parallelism,
  hashLen: uint32 = defaultParams.hashLen,
  algoType: Argon2Type = defaultParams.algoType,
  version: Argon2Version = defaultParams.version,
): Argon2Params {.inline.} =
  result = Argon2Params(
    timeCost: timeCost,
    memoryCostK: memoryCostK,
    parallelism: parallelism,
    hashLen: hashLen,
    algoType: algoType,
    version: version,
  )

# C FFI
# https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h
{.push
  dynLib: libargon2
  importc
.}

# https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/src/argon2.c#L447
func argon2_encodedlen(
  timeCost: cuint,
  memCost: cuint,
  parellelism: cuint,
  saltLen: cuint,
  hashLen: cuint,
  algoType: Argon2Type
): culong
# TODO replace culong with csize_t in upcoming version...

# https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/include/argon2.h#417
func argon2_error_message(
  returnCode: ReturnCode
): cstring

# https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/include/argon2.h#347
func argon2_verify(
  encoded: cstring,
  pwd: pointer,
  pwdLen: culong,
  algoType: Argon2Type,
): ReturnCode

# https://github.com/P-H-C/phc-winner-argon2/blob/62358ba2123abd17fccf2a108a301d4b52c01a7c/src/argon2.c#L100
proc argon2_hash(
  timeCost: cuint,
  memCost: cuint,
  parellelism: cuint,
  pwd: pointer,
  pwdLen: culong,
  salt: pointer,
  saltLen: culong,
  hash: pointer,
  hashLen: culong,
  encoded: cstring,
  encodedLen: culong,
  algoType: Argon2Type,
  version: cuint
): ReturnCode

{.pop.}

{.push
  inline
.}

converter toCtrDataPtr[T: string|seq|openarray](x: var T): ptr =
  if x.len > 0:
    result = x[0].addr

func getEncodedLen*(
  argon2Params: Argon2Params,
  salt: seq[byte] | string,
): uint32 {.inline.} =
  result = argon2_encodedlen(
    argon2Params.timeCost.cuint,
    argon2Params.memoryCostK.cuint,
    argon2Params.parallelism.cuint,
    salt.len.cuint,
    argon2Params.hashLen.cuint,
    argon2Params.algoType,
  ).uint32

func getMessage(
  returnCode: cint
): string {.inline.} =
  let msg: cstring = returnCode.argon2_error_message
  let size = msg.len
  result = newString(size)
  moveMem(result[0].addr, msg, size)

template ensure(
  condition: bool,
  errorMsg: string,
  exception: type Exception
) =
  if unlikely condition == false:
    raise exception.newException errorMsg

func execArgon2(
  pass: var seq[byte],
  salt: var seq[byte],
  argon2Params: Argon2Params,
  argon2Output: var Argon2Output,
): void {.inline.} =

  ensure pass.len > 0,
    "Password is empty",
    Argon2Error

  var encodedLen = argon2Output.encoded.len
  # account for null-byte expected on C side
  if encodedLen > 0:
    inc encodedLen

  let returnCode = argon2_hash(
    argon2Params.timeCost,
    argon2Params.memoryCostK,
    argon2Params.parallelism,
    toCtrDataPtr pass,
    pass.len.culong,
    toCtrDataPtr salt,
    salt.len.culong,
    toCtrDataPtr argon2Output.hash,
    argon2Params.hashLen,
    argon2Output.encoded,
    encodedLen.culong,
    argon2Params.algoType,
    argon2Params.version.cuint,
  )
  ensure returnCode == 0,
    returnCode.getMessage,
    Argon2Error

template localCastToSeqByte(pass, salt) =
  var lpass {.inject.} = cast[seq[byte]](pass)
  var lsalt {.inject.} = cast[seq[byte]](salt)

template setupHash(
  hash: var seq[byte],
  argon2Params: Argon2Params
) =
  hash = newSeq[byte](argon2Params.hashLen)
  hash.shallow

template setupEncoded(
  encoded: var string,
  argon2Params: Argon2Params,
  salt: seq[byte],
) =
  let encodedLen = argon2Params.getEncodedLen salt
  # discount extra nullbyte accounted from getEncodedLen
  # but keep enough cap to avoid memory corruption
  # IF argon2 were to try writing up to it
  # We will have to re-account for it before sending it
  # off to the C lib
  encoded = newStringOfCap encodedLen
  encoded.setLen encodedLen - 1
  encoded.shallow

func getRawHash*(
  pass, salt: seq[byte] | string,
  argon2Params: Argon2Params,
): seq[byte] {.inline.} =
  localCastToSeqByte pass, salt

  var hash: seq[byte]
  hash.setupHash(argon2Params)

  var argon2Output = Argon2Output(
    hash: hash
  )
  execArgon2(
    lpass,
    lsalt,
    argon2Params,
    argon2Output,
  )
  result = hash

func getEncodedHash*(
  pass, salt: seq[byte] | string,
  argon2Params: Argon2Params = defaultParams,
): string =
  localCastToSeqByte pass, salt
  var encoded: string
  encoded.setupEncoded(argon2Params, lsalt)

  var argon2Output = Argon2Output(
    encoded: encoded
  )
  execArgon2(
    lpass,
    lsalt,
    argon2Params,
    argon2Output
  )
  result = encoded

func getOutput*(
  pass, salt: seq[byte] | string,
  argon2Params: Argon2Params = defaultParams,
): Argon2Output =
  localCastToSeqByte pass, salt

  var hash: seq[byte]
  hash.setupHash(argon2Params)

  var encoded: string
  encoded.setupEncoded(argon2Params, lsalt)

  result = Argon2Output(
    hash: hash,
    encoded: encoded,
  )
  execArgon2(
    lpass,
    lsalt,
    argon2Params,
    result,
  )

func isVerified*(
  encoded: string,
  pass: seq[byte] | string,
): bool =
  var lpass = cast[seq[byte]](pass)
  ensure encoded.len > 8,
    "Encoded parameter passed is too short...",
    Argon2Error

  var algo: Argon2Type
  case encoded[1 .. 8]:
    of "argon2id":
      algo = Argon2id
    of "argon2i$":
      algo = Argon2i
    of "argon2d$":
      algo = Argon2d

  let returnCode = argon2_verify(
    encoded,
    lpass.toCtrDataPtr,
    lpass.len.culong,
    algo,
  )
  if likely returnCode == 0:
    return true
  elif likely returnCode == -35:
    return false
  else:
    raise Argon2Error.newException returnCode.getMessage

{.pop.}

