import
  argon2_bind,
  random,
  unittest

var rng = initRand(74961379746663)

type Input = object
  pass, salt: seq[byte]
  params: Argon2Params
type Fixture = object
  input: Input
  output: Argon2Output

# CONFIG
const 
  FIXTURE_SIZE = 100
  PASS_MIN = 1
  PASS_MAX = 64
  SALT_MIN = 8
  SALT_MAX = 64
  TCOST_MIN = 1
  TCOST_MAX = 12
  MCOST_MIN = 8
  MCOST_MAX = 512
  THRD_MIN = 1
  HLEN_MIN = 4
  HLEN_MAX = 64
  ALGO_MAX = 2

# This MUST be updated in case of any changes
# to the config constants, or the determinism
# check skipped...
const LAST_FIXTURE = Argon2Output(
  hash: @[227.byte, 122, 41, 223, 151, 155, 156, 103],
  encoded: "$argon2id$v=19$m=140,t=1,p=1$PtGZkwCsj3QzwquePW0gdNXuuYjj9HdgbqGGb5bIHPmLdkE$43op35ebnGc"
)

const REPEAT_COUNT = 3

suite "test for consistency between procs and multiple calls":
  var fixtures: array[FIXTURE_SIZE, Fixture]
  for i in fixtures.low .. fixtures.high:
    {.unroll.}
    let plen = rng.rand(PASS_MIN .. PASS_MAX).uint8
    fixtures[i].input.pass = newSeq[byte](plen)
    for j in 0.uint8 .. (plen - 1):
      fixtures[i].input.pass[j] = rng.next.byte

    let slen = rng.rand(SALT_MIN .. SALT_MAX).uint8
    fixtures[i].input.salt = newSeq[byte](slen)
    for j in 0.uint8 .. (slen - 1):
      fixtures[i].input.salt[j] = rng.next.byte
    
    let mcost = rng.rand(MCOST_MIN .. MCOST_MAX).uint32
    let thrdMax = mcost.int div 8

    fixtures[i].input.params = Argon2Params(
      timeCost: rng.rand(TCOST_MIN .. TCOST_MAX).uint32,
      memoryCostK: mcost,
      parallelism: rng.rand(THRD_MIN .. thrdMax).uint32,
      hashLen: rng.rand(HLEN_MIN .. HLEN_MAX).uint32,
      algoType: rng.rand(ALGO_MAX).Argon2Type,
      version: rng.sample([Argon2Version10, Argon2Version13]),
    )
    
    fixtures[i].output =
      getOutput(
        fixtures[i].input.pass,
        fixtures[i].input.salt,
        fixtures[i].input.params,
      )
  test "check fixture determinism":
    check fixtures[fixtures.high].output == LAST_FIXTURE
  test "check getRawHash consistency":
    for f in fixtures:
      check f.output.hash == getRawHash(
        f.input.pass,
        f.input.salt,
        f.input.params,
      )
  test "check getEncodedHash consistency":
    for f in fixtures:
      check f.output.encoded == getEncodedHash(
        f.input.pass,
        f.input.salt,
        f.input.params,
      )
  test "check getOutput consistency":
    for f in fixtures:
      check f.output == getOutput(
        f.input.pass,
        f.input.salt,
        f.input.params,
      )
  test "check multiple call consistency":
    for i in 0 .. REPEAT_COUNT:
      for f in fixtures:
        check f.output == getOutput(
          f.input.pass,
          f.input.salt,
          f.input.params,
        )
  test "check multiple serial call consistency":
    for f in fixtures:
      for i in 0 .. REPEAT_COUNT:
        check f.output == getOutput(
          f.input.pass,
          f.input.salt,
          f.input.params,
        )
