SHA-3 in pure Nim based on [Pycryptodome](https://github.com/Legrandin/pycryptodome/blob/master/src/keccak.c) 

```Nim
let message = "hello world"
var ctx = newSha3_256Ctx(message)
doAssert ctx.hexDigest() == "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938"
```
