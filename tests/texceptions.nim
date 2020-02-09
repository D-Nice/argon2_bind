import
  argon2_bind,
  ./fixtures/exceptions,
  unittest

# attempts to cover as many errors as possible from
# https://github.com/P-H-C/phc-winner-argon2/blob/master/include/argon2.h#L100
# during runtime, excluding unperformant cases, such as huge strings
# or those which shouldn't be possible to reach from this Nim library

template checkErrorMsg(
  f: Fixture
) =
  var p: Argon2Params
  if f.params != Argon2Params(): p = f.params else: p = setupArgon2Params()
  try:
    case f.fn
    of "getOutput":
      discard getOutput(f.args[0], f.args[1], p)
    of "getRawHash":
      discard getRawHash(f.args[0], f.args[1], p)
    of "getEncodedHash":
      discard getEncodedHash(f.args[0], f.args[1], p)
    of "isVerified":
      discard isVerified(f.args[0], f.args[1])
    fail()
  except Argon2Error:
    check getCurrentExceptionMsg() == f.msg
  except:
    fail()

suite "test exceptions":
  test "verify exception messages":
    for fixture in Fixtures:
      checkErrorMsg fixture
