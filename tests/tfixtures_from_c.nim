import
  argon2_bind,
  ./fixtures/from_c,
  strutils,
  unittest

suite "test C fixtures: getOutput":
  var res: seq[Argon2Output]
  for test in testFixtures:
    res.add getOutput(
      test.pass,
      test.salt,
      test.argon2Params,
    )
  test "compare hash output":
    for i in res.low .. res.high:
      let resHash = cast[string](res[i].hash)
      check resHash.toHex.toLower == testFixtures[i].expectedHash.toLower
  test "compare encoding output":
    for i in res.low .. res.high:
      check res[i].encoded == testFixtures[i].expectedEncoded
  test "verify output":
    for i in res.low .. res.high:
      check res[i].encoded.isVerified(testFixtures[i].pass)
  test "compare errors":
    let errs = hashErrFixtures
    for err in errs:
      try:
        discard getOutput(
          err.pass,
          err.salt,
          err.argon2Params,
        )
        check false
      except Argon2Error:
        check getCurrentExceptionMsg() == err.expectedMsg

suite "test C fixtures: getRawHash":
  var res: seq[seq[byte]]
  for test in testFixtures:
    res.add getRawHash(
      test.pass,
      test.salt,
      test.argon2Params,
    )
  test "compare output":
    for i in res.low .. res.high:
      let resHash = cast[string](res[i])
      check resHash.toHex.toLower == testFixtures[i].expectedHash.toLower
  test "compare errors":
    let errs = hashErrFixtures
    for err in errs:
      try:
        discard getRawHash(
          err.pass,
          err.salt,
          err.argon2Params,
        )
        check false
      except Argon2Error:
        check getCurrentExceptionMsg() == err.expectedMsg

suite "test C fixtures: getEncodedHash":
  var res: seq[string]
  for test in testFixtures:
    res.add getEncodedHash(
      test.pass,
      test.salt,
      test.argon2Params,
    )
  test "compare output":
    for i in res.low .. res.high:
      check res[i] == testFixtures[i].expectedEncoded
  test "verify output":
    for i in res.low .. res.high:
      check res[i].isVerified(testFixtures[i].pass)
  test "compare errors":
    let errs = hashErrFixtures
    for err in errs:
      try:
        discard getEncodedHash(
          err.pass,
          err.salt,
          err.argon2Params,
        )
        check false
      except Argon2Error:
        check getCurrentExceptionMsg() == err.expectedMsg

suite "test C fixtures: isVerified":
  test "verify fixtures":
    for test in testFixtures:
      check test.expectedEncoded.isVerified(test.pass)
  test "compare errors":
    let errs = verifyErrFixtures
    for err in errs:
      try:
        let ver = isVerified(err.encoded, err.pass)
        check ver == false
        # ensure we didnt expect an explicit error
        # empty msg means it's just a plain verification fail
        check err.expectedMsg == ""
      except Argon2Error:
        check getCurrentExceptionMsg() == err.expectedMsg
