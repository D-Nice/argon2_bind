## This module provides an interface to the Argon2 reference C implementation.
## It depends on libargon2, and can be used dynamically with the shared library
## or statically compiled with the static library. The aim is to provide a
## high-level and fully-featured implementation of the C reference backed
## by comprehensive documentation, tests, and fuzzing.
##
## Basic usage
## ===========
##
## The basic flow of using this module which mimicks the argon2 cli is:
##
## 1. Set the wanted Argon2 hash parameters
## 2. Set a password and salt
## 3. Call `getOutput` with the previous parameters
## 4. Verify the encoded portion of the returned object via `isVerified`
## 5. Utilize the verified output
##
## Example
## --------------------
##
## .. code-block:: Nim
##
##  import argon2_bind
##
##  const params = setupArgon2Params(
##    timeCost = 3,
##    memoryCostK = 1 shl 8,
##    parallelism = 2,
##    algoType = Argon2id,
##  )
##
##  const salt = "somesalt"
##  var pass = "password"
##
##  var res: Argon2Output
##  try:
##    res = pass.getOutput(salt, params)
##  except Argon2Error:
##    echo getCurrentExceptionMsg()
##    quit 1
##
##  if res.encoded.isVerified(pass):
##    echo res.hash
##
##  # Output:
##  # @[163, 22, 29, 233, 157, 14, 124, 7, 98, 54, 75, 44, 75, 62, 162, 185,
##  # 80, 0, 89, 115, 248, 135, 157, 84, 40, 127, 216, 189, 86, 146, 31, 54]
##
when defined(Windows):
  const libargon2 = "libargon2.dll"
else:
  const libargon2 = "libargon2.so(|.1)"

# EXPORTED TYPES

type
  Argon2Error* = object of CatchableError
    ## Catchable error arising from argon2_bind module.

type
  Argon2Type* = enum
    ## Hashing algorithm variants available.
    ##
    ## Argon2d is faster and uses data-depending memory access, which makes it
    ## highly resistant against GPU cracking attacks and suitable for
    ## applications with no threats from side-channel timing attacks (eg.
    ## cryptocurrencies). Argon2i instead uses data-independent memory access,
    ## which is preferred for password hashing and password-based key
    ## derivation, but it is slower as it makes more passes over the memory to
    ## protect from tradeoff attacks. Argon2id is a hybrid of Argon2i and
    ## Argon2d, using a combination of data-depending and data-independent
    ## memory accesses, which gives some of Argon2i's resistance to
    ## side-channel cache timing attacks and much of Argon2d's resistance to
    ## GPU cracking attacks.
    Argon2d,
    Argon2i,
    Argon2id,

type
  Argon2Version* = enum
    ## Hashing algorithm version.
    ##
    ## See also:
    ## * `Argon2Params <#Argon2Params>`_
    ## * `Argon2DefaultParams <#Argon2DefaultParams>`_
    ## * `Argon2CurrentVersion <#Argon2CurrentVersion>`_
    Argon2Version10 = 0x10,
    Argon2Version13 = 0x13,


type
  Argon2Params* {.bycopy.} = object
    ## Hashing parameters required to be passed.
    ##
    ## **Constraints**
    ##
    ## `timeCost` must be at least 1.
    ##
    ## `memoryCostK` is in KiB, and the minimum must adhere to the formula
    ## `memoryCostK/parallelism >= 8`.
    ##
    ## `parallelism` refers to the lanes and threads to be utilized. As
    ## mentioned via the `memoryCostK` constraint, each lane must have 8KiB of
    ## memory available to it.
    ##
    ## `hashLen` minimum is 4.
    ##
    ## See also:
    ## * `setupArgon2Params
    ## <#setupArgon2Params,uint32,uint32,uint32,uint32,Argon2Type,Argon2Version>`_
    ## * `getOutput <#getOutput,,,Argon2Params>`_
    ## * `getRawHash <#getRawHash,,,Argon2Params>`_
    ## * `getEncodedHash <#getEncodedHash,,,Argon2Params>`_
    timeCost*, memoryCostK*, parallelism*, hashLen*: uint32
    algoType*: Argon2Type
    version*: Argon2Version

type
  Argon2Output* = object
    ## `hash` will contain the finalized hash value as a sequence of bytes.
    ##
    ## `encoded` key will contain the ad-hoc encoded output as a string.
    ## It is basically a stringified structure of all parameters, excluding the
    ## password, but including the hash value as the last variable in base64.
    ##
    ## See also:
    ## * `getOutput <#getOutput,,,Argon2Params>`_
    ##
    # By wrapping potential outputs in this object
    # we are more easily able to pass nil as a parameter in nim
    # in which case the C library will understand not to
    # provide said output
    hash*: seq[byte]
    encoded*: string

# PRIVATE TYPES

type
  ReturnCode = cint

const Argon2CurrentVersion* = Argon2Version13
  ## Denotes the current version, which is the one recommended to be used.
  ##
  ## Output will of course differ between each version, keep note of the
  ##
  ## version used. It is also noted in the encoded output.
  ##
  ## See also:
  ## * `Argon2Params <#Argon2Params>`_
  ## * `Argon2DefaultParams <#Argon2DefaultParams>`_

const Argon2DefaultParams* = Argon2Params(
  timeCost: 3,
  memoryCostK: 4096,
  parallelism: 1,
  hashLen: 32,
  algoType: Argon2i,
  version: Argon2CurrentVersion,
)
  ## The default parameters to be utilized by the module. Utilized as a
  ## fallback in linked functions below.
  ##
  ## These values match the current argon2 cli defaults.
  ##
  ## See also:
  ## * `setupArgon2Params
  ## <#setupArgon2Params,uint32,uint32,uint32,uint32,Argon2Type,Argon2Version>`_
  ## * `getOutput <#getOutput,,,Argon2Params>`_
  ## * `getRawHash <#getRawHash,,,Argon2Params>`_
  ## * `getEncodedHash <#getEncodedHash,,,Argon2Params>`_

func setupArgon2Params*(
  timeCost: uint32 = Argon2DefaultParams.timeCost,
  memoryCostK: uint32 = Argon2DefaultParams.memoryCostK,
  parallelism: uint32 = Argon2DefaultParams.parallelism,
  hashLen: uint32 = Argon2DefaultParams.hashLen,
  algoType: Argon2Type = Argon2DefaultParams.algoType,
  version: Argon2Version = Argon2DefaultParams.version,
): Argon2Params {.inline.} =
  ## Returns the parameterized state needed by the hashing function,
  ## with each passed parameter being optional and having a fallback
  ## to the defaults if omitted.
  ##
  ## See also:
  ## * `Argon2DefaultParams <#Argon2DefaultParams>`_
  ## * `Argon2Params <#Argon2Params>`_
  runnableExamples:
    # no args yields full fallback
    let firstParams = setupArgon2Params()
    doAssert firstParams == Argon2DefaultParams
    # partial arg yields fallback on ones not provided
    let secondParams = setupArgon2Params(
      hashLen = 4,
      memoryCostK = 1 shl 9,
    )
    doAssert secondParams == Argon2Params(
      timeCost: 3,
      memoryCostK: 1 shl 9,
      parallelism: 1,
      hashLen: 4,
      algoType: Argon2i,
      version: Argon2CurrentVersion,
    )
  # runnableExamples end

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

{.pop.} ## pops dynlib and importc

{.push
  inline
.}

converter toCtrDataPtr[T: string|seq|openArray](x: var T): ptr =
  ## Expects a native container data type, and returns a ptr to the address
  ## of where its data should be allocated.
  ##
  ## Returns a nil ptr in the case of an empty container.
  ##
  ## The argon2 C lib handles nil ptrs appropriately in the cases where this
  ## converter is used.
  if x.len > 0:
    result = x[0].addr

func getEncodedLen*(
  argon2Params: Argon2Params,
  salt: seq[byte] | string,
): uint32 =
  ## Requires parameterized argon2 object.
  ##
  ## Requires a salt parameter as either a byte sequence or string.
  ##
  ## Returns the expected encoded output length, depending on input parameters.
  ##
  ## Mainly for internal use.
  result = argon2_encodedlen(
    argon2Params.timeCost.cuint,
    argon2Params.memoryCostK.cuint,
    argon2Params.parallelism.cuint,
    salt.len.cuint,
    argon2Params.hashLen.cuint,
    argon2Params.algoType,
  ).uint32

func getMessage(
  returnCode: ReturnCode
): string =
  ## Expects returnCode, and then calls the C lib to resolve its underlying
  ## human-readable error message.
  let msg: cstring = returnCode.argon2_error_message
  let size = msg.len
  result = newString(size)
  moveMem(result[0].addr, msg, size)

template ensure(
  condition: bool,
  errorMsg: string,
  exception: type Exception
) =
  ## Helper for ensuring a specific condition is met, and if not the
  ## passed exception and error message are raised.
  if unlikely condition == false:
    raise exception.newException errorMsg

template ensureAboveMinLen(pass: seq[byte]) =
  ensure pass.len > 0,
    "Password is empty",
    Argon2Error

func execArgon2(
  pass: var seq[byte],
  salt: var seq[byte],
  argon2Params: Argon2Params,
  argon2Output: var Argon2Output,
): void =
  ## Private function which does the actual call to the C lib.
  ##
  ## Shared entrypoint for all the hashing functions:
  ##
  ## getOutput
  ## getRawHash
  ## getEncodedHash
  pass.ensureAboveMinLen
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
  ## Helper for streamlined code maintenance
  ## (meaning there's multiple instances of these
  ## across functions, and by packing them in
  ## this template, we only need to change underlying
  ## code here once for them).
  ##
  ## takes the passed variables, and injects
  ## local instances of them prefixed with 'l'
  ## that are cast to seq[byte].
  var lpass {.inject.} = cast[seq[byte]](pass)
  var lsalt {.inject.} = cast[seq[byte]](salt)

template setupHash(
  hash: var seq[byte],
  argon2Params: Argon2Params
) =
  ## Helper for streamlined code maintenance.
  ##
  ## Initalizes the hash variable according to the parameters passed.
  hash = newSeq[byte](argon2Params.hashLen)
  hash.shallow

template setupEncoded(
  encoded: var string,
  argon2Params: Argon2Params,
  salt: seq[byte],
) =
  ## Helper for streamlined code maintenance.
  ##
  ## Initalizes the encoded variable according to the parameters passed.
  let encodedLen = argon2Params.getEncodedLen salt
  # discount extra nullbyte accounted from getEncodedLen
  # but keep enough cap to avoid memory corruption
  # IF argon2 were to try writing up to it
  # We will have to re-account for it before sending it
  # off to the C lib
  encoded = newStringOfCap encodedLen
  encoded.setLen encodedLen - 1
  encoded.shallow

{.push
  raises: [Argon2Error]
.}

func getOutput*(
  pass, salt: seq[byte] | string,
  argon2Params: Argon2Params = Argon2DefaultParams,
): Argon2Output =
  ## Requires a password and salt, either as a sequence of bytes or string.
  ## The password must have at least 1 byte. The salt must be at least 8 bytes.
  ##
  ## Optionally takes the typed parameters for argon2, does a fallback to
  ## `Argon2DefaultParams <#Argon2DefaultParams>`_ if none are passed. Only
  ## at this point are the parameters sanity checked, in their pass to the
  ## C lib.
  ##
  ## Returns an `Argon2Output <#Argon2Output>`_ object.
  ##
  ## Raises an `Argon2Error <#Argon2Error>`_ on internal exception.
  ##
  ## See also:
  ## * `getRawHash <#getRawHash,,,Argon2Params>`_
  ## * `getEncodedHash <#getEncodedHash,,,Argon2Params>`_
  runnableExamples:
    let
      params = setupArgon2Params(hashLen = 4)
      salt = "somesalt"
      pass = "abc"
    let res = pass.getOutput(salt, params)
    doAssert res.hash == @[27.byte, 96, 149, 111]
    doAssert res.encoded == "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$G2CVbw"
  # runnableExamples end

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

func getRawHash*(
  pass, salt: seq[byte] | string,
  argon2Params: Argon2Params = Argon2DefaultParams,
): seq[byte] =
  ## Refer to `getOutput <#getOutput,,,Argon2Params>`_ for input parameters
  ## which are shared here.
  ##
  ## Returns a byte sequence of the computed hash value.
  ##
  ## Raises an `Argon2Error <#Argon2Error>`_ on internal exception.
  ##
  ## See also:
  ## * `getOutput <#getOutput,,,Argon2Params>`_
  ## * `getEncodedHash <#getEncodedHash,,,Argon2Params>`_
  runnableExamples:
    let
      params = setupArgon2Params(hashLen = 4)
      salt = "somesalt"
      pass = "abc"
    let res = pass.getRawHash(salt, params)
    doAssert res == @[27.byte, 96, 149, 111]
  # runnableExamples end

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
  argon2Params: Argon2Params = Argon2DefaultParams,
): string =
  ## Refer to `getOutput <#getOutput,,,Argon2Params>`_ for guidance on the
  ## input parameters.
  ##
  ## Returns a string of the argon2 encoded value. Note, this is not the
  ## hash value.
  ##
  ## Raises an `Argon2Error <#Argon2Error>`_ on internal exception.
  ##
  ## See also:
  ## * `getOutput <#getOutput,,,Argon2Params>`_
  ## * `getRawHash <#getRawHash,,,Argon2Params>`_
  runnableExamples:
    var expected = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ"
    expected &= "$vi0N5Av/NnxgttHDWyVte+OheXu6wuyyFSWJsNEhCCI"
    let
      salt = "somesalt"
      pass = "abc"
    let res = pass.getEncodedHash(salt)
    doAssert res == expected
    let params = setupArgon2Params(hashLen = 4)
    let res2 = pass.getEncodedHash(salt, params)
    doAssert res2 == "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$G2CVbw"
  # runnableExamples end

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

func isVerified*(
  encoded: string,
  pass: seq[byte] | string,
): bool =
  ## Requires the encoded hash output as a string from either
  ## `getEncodedHash <#getEncodedHash,,,Argon2Params>`_ or
  ## `getOutput <#getOutput,,,Argon2Params>`_.
  ## Requires password of type byte sequence or string. Must be at least 1
  ## byte.
  ##
  ## Returns a bool, with true indicating success.
  ##
  ## Raises an `Argon2Error <#Argon2Error>`_ on internal exception.
  runnableExamples:
    let pass = "pass"
    let encodedHash = getEncodedHash(pass, "somesalt")
    doAssert encodedHash.isVerified(pass) == true
    doAssert encodedHash.isVerified("wrongpass") == false
    try:
      discard encodedHash[0 .. ^2].isVerified(pass)
      doAssert false
    except Argon2Error:
      doAssert true
    except:
      doAssert false
  # runnableExamples end

  var lpass = cast[seq[byte]](pass)
  lpass.ensureAboveMinLen

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

{.pop.} ## pops raise pragma
{.pop.} ## pops inline pragma

