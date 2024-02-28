import std/strutils

include keccak


type Sha3_384Ctx = object
  state: KeccakState
  blockSize: int
  digestSize: int
  padding: byte


const
  DigestSize = 48
  BlockSize = 104
  Padding = 0x06'u8
  Rounds = 24'u8


proc update*(ctx: var Sha3_384Ctx, data: openArray[byte]) =
  discard ctx.state.keccakAbsorb(data)


proc update*(ctx: var Sha3_384Ctx, data: string) =
  discard ctx.state.keccakAbsorb(data.toOpenArrayByte(0, data.len.pred))


proc digest*(ctx: var Sha3_384Ctx): array[DigestSize, byte] =
  discard keccakDigest(ctx.state, result, ctx.digestSize, ctx.padding)


proc hexDigest*(ctx: var Sha3_384Ctx): string =
  ## produces a hex string of length ctx.digestSize * 2
  result = newStringOfCap(ctx.digestSize + ctx.digestSize)
  let digest = ctx.digest()
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc newSha3_384Ctx*(data: openArray[byte] = @[]): Sha3_384Ctx =
  result.blockSize = BlockSize
  result.digestSize = DigestSize
  result.padding = Padding
  
  result.state = keccakInit(DigestSize + DigestSize, Rounds)

  if data.len > 0:
    result.update(data)


proc newSha3_384Ctx*(data: string): Sha3_384Ctx =
  return newSha3_384Ctx(data.toOpenArrayByte(0, data.len.pred))


when isMainModule:
  let message = "hello world"

  var ctx = newSha3_384Ctx(message)
  doAssert ctx.hexDigest() == "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b"
