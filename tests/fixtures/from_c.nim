import argon2_bind

# sourced from https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c
const OUT_LEN = 32

type TestParams* = object
  argon2Params*: Argon2Params
  pass*, salt*, expectedHash*, expectedEncoded*: string

type VerifyErrParams* = object
  pass*, encoded*, expectedMsg*: string

type HashErrParams* = object
  argon2Params*: Argon2Params
  pass*, salt*, expectedMsg*: string

var testFixtures*: seq[TestParams]
var verifyErrFixtures*: seq[VerifyErrParams]
var hashErrFixtures*: seq[HashErrParams]

# Argon2i V0x10
testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
    expectedEncoded: "$argon2i$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 20,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
    expectedEncoded: "$argon2i$v=16$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 18,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
    expectedEncoded: "$argon2i$v=16$m=262144,t=2,p=1$c29tZXNhbHQ$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 8,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
    expectedEncoded: "$argon2i$v=16$m=256,t=2,p=1$c29tZXNhbHQ$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 8,
      parallelism: 2,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
    expectedEncoded: "$argon2i$v=16$m=256,t=2,p=2$c29tZXNhbHQ$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 1,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
    expectedEncoded: "$argon2i$v=16$m=65536,t=1,p=1$c29tZXNhbHQ$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 4,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
    expectedEncoded: "$argon2i$v=16$m=65536,t=4,p=1$c29tZXNhbHQ$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "differentpassword",
    salt: "somesalt",
    expectedHash: "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
    expectedEncoded: "$argon2i$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version10,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "diffsalt",
    expectedHash: "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
    expectedEncoded: "$argon2i$v=16$m=65536,t=2,p=1$ZGlmZnNhbHQ$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc"
  )
)




# Argon2i V0x13
testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
    expectedEncoded: "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 20,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
    expectedEncoded: "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 18,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
    expectedEncoded: "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 8,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
    expectedEncoded: "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 8,
      parallelism: 2,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
    expectedEncoded: "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 1,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
    expectedEncoded: "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 4,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
    expectedEncoded: "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "differentpassword",
    salt: "somesalt",
    expectedHash: "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
    expectedEncoded: "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2i,
    ),
    pass: "password",
    salt: "diffsalt",
    expectedHash: "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
    expectedEncoded: "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE"
  )
)

# Argon2id V0x13
testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
    expectedEncoded: "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 18,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c",
    expectedEncoded: "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 8,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
    expectedEncoded: "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 8,
      parallelism: 2,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
    expectedEncoded: "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 1,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
    expectedEncoded: "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg",
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 4,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "somesalt",
    expectedHash: "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c",
    expectedEncoded: "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "differentpassword",
    salt: "somesalt",
    expectedHash: "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde",
    expectedEncoded: "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94"
  )
)

testFixtures.add(
  TestParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 16,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "diffsalt",
    expectedHash: "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c",
    expectedEncoded: "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw"
  )
)

# https://github.com/P-H-C/phc-winner-argon2/blob/master/src/test.c#L116
# Argon2i V0x10 error state tests
verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
    expectedMsg: "Decoding failed",
  )
)

verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
    expectedMsg: "Decoding failed",
  )
)

verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
    expectedMsg: "Salt is too short",
  )
)

verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo",
    expectedMsg: "",
  )
)

# Argon2i V0x13 error state tests
verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
    expectedMsg: "Decoding failed",
  )
)

verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
    expectedMsg: "Decoding failed",
  )
)

verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$v=19$m=65536,t=2,p=1$$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
    expectedMsg: "Salt is too short",
  )
)

verifyErrFixtures.add(
  VerifyErrParams(
    pass: "password",
    encoded: "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM",
    expectedMsg: "",
  )
)

hashErrFixtures.add(
  HashErrParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "diffsalt",
    expectedMsg: "Memory cost is too small",
  )
)

# The password pointer mismatch should not be able to occur
# with this lib, therefore we will just check for an empty password
# presuming it is user error
hashErrFixtures.add(
  HashErrParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 12,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    salt: "diffsalt",
    expectedMsg: "Password is empty",
  )
)

hashErrFixtures.add(
  HashErrParams(
    argon2Params: Argon2Params(
      version: Argon2Version13,
      timeCost: 2,
      memoryCostK: 1 shl 12,
      parallelism: 1,
      hashLen: OUT_LEN,
      algoType: Argon2id,
    ),
    pass: "password",
    salt: "s",
    expectedMsg: "Salt is too short",
  )
)
