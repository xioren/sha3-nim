import std/strutils

include keccakf


type Sha3_224Ctx = object
  state: KeccakState
  blockSize: int
  digestSize: int
  padding: byte


const
  DigestSize = 28
  BlockSize = 144
  Padding = 0x06'u8
  Rounds = 24'u8


proc update*(ctx: var Sha3_224Ctx, data: openArray[byte]) =
  discard ctx.state.keccakAbsorb(data)


proc update*(ctx: var Sha3_224Ctx, data: string) =
  discard ctx.state.keccakAbsorb(data.toOpenArrayByte(0, data.len.pred))


proc digest*(ctx: var Sha3_224Ctx): array[DigestSize, byte] =
  discard keccakDigest(ctx.state, result, ctx.digestSize, ctx.padding)


proc hexDigest*(ctx: var Sha3_224Ctx): string =
  ## produces a hex string of length ctx.digestSize * 2
  result = newStringOfCap(ctx.digestSize + ctx.digestSize)
  let digest = ctx.digest()
  for b in digest:
    result.add(b.toHex(2).toLowerAscii())

  return result


proc newSha3_224Ctx*(data: openArray[byte] = @[]): Sha3_224Ctx =
  result.blockSize = BlockSize
  result.digestSize = DigestSize
  result.padding = Padding
  
  result.state = keccakInit(DigestSize + DigestSize, Rounds)

  if data.len > 0:
    result.update(data)


proc newSha3_224Ctx*(data: string): Sha3_224Ctx =
  return newSha3_224Ctx(data.toOpenArrayByte(0, data.len.pred))


when isMainModule:
  let message = "hello world"

  var ctx = newSha3_224Ctx(message)
  doAssert ctx.hexDigest() == "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5"