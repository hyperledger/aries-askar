import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

const PublicKey = CStruct({
  MontgomeryPoint: CArray(ref.types.uint8, 32),
})

export const X25519KeyPair = CStruct({
  optional: ref.types.uint8,
  secret: CArray(ref.types.uint8, 32),
  public: PublicKey,
})
