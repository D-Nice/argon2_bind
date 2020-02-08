import
  argon2_bind

# errors covered
# ARGON2_PWD_TOO_SHORT
# ARGON2_SALT_TOO_SHORT
# ARGON2_TIME_TOO_SMALL
# ARGON2_MEMORY_TOO_LITTLE
# ARGON2_LANES_TOO_FEW
# ARGON2_LANES_TOO_MANY
# ARGON2_ENCODING_FAILED
#
# Many upper bounds missing, as the utilized types
# stop such a program from even compiling.
# With the high-level API lanes is equivalent to
# threads (threads are set to the lanes value,
# but the lanes bound is checked before threads
# therefore we only see a lanes error)
type
  Fixture* = object
    fn*: string
    args*: seq[string]
    params*: Argon2Params
    msg*: string

const Fixtures* = [
  Fixture(
    fn: "getOutput",
    args: @["", "saltsalt"],
    msg: "Password is empty",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["", "saltsalt"],
    msg: "Password is empty",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["", "saltsalt"],
    msg: "Password is empty",
  ),
  Fixture(
    fn: "getOutput",
    args: @["password", "altsalt"],
    msg: "Salt is too short",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["password", "altsalt"],
    msg: "Salt is too short",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["password", "altsalt"],
    msg: "Salt is too short",
  ),
  Fixture(
    fn: "getOutput",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(timeCost = 0),
    msg: "Time cost is too small",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(timeCost = 0),
    msg: "Time cost is too small",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(timeCost = 0),
    msg: "Time cost is too small",
  ),
  Fixture(
    fn: "getOutput",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(memoryCostK = 7),
    msg: "Memory cost is too small",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(memoryCostK = 7),
    msg: "Memory cost is too small",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(memoryCostK = 7),
    msg: "Memory cost is too small",
  ),
  Fixture(
    fn: "getOutput",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(memoryCostK = 0),
    msg: "Memory cost is too small",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(memoryCostK = 0),
    msg: "Memory cost is too small",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(memoryCostK = 0),
    msg: "Memory cost is too small",
  ),
  Fixture(
    fn: "getOutput",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(parallelism = 0),
    msg: "Too few lanes",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(parallelism = 0),
    msg: "Too few lanes",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(parallelism = 0),
    msg: "Too few lanes",
  ),
  Fixture(
    fn: "getOutput",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(parallelism = 1 shl 24, memoryCostK = 1 shl 31),
    msg: "Too many lanes",
  ),
  Fixture(
    fn: "getRawHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(parallelism = 1 shl 24, memoryCostK = 1 shl 31),
    msg: "Too many lanes",
  ),
  Fixture(
    fn: "getEncodedHash",
    args: @["password", "saltsalt"],
    params: setupArgon2Params(parallelism = 1 shl 24, memoryCostK = 1 shl 31),
    msg: "Too many lanes",
  ),
  Fixture(
    fn: "isVerified",
    args: @["$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ" &
            "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
            "password"],
    msg: "Decoding failed",
  ),
  Fixture(
    fn: "isVerified",
    args: @["$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" &
            "wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
            "password"],
    msg: "Decoding failed",
  ),
  Fixture(
    fn: "isVerified",
    args: @["$argon2i$v=19$m=65536,t=2,p=1$" &
            "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
            "password"],
    msg: "Salt is too short",
  ),
]
