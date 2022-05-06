import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

const EdwardsPoint = CStruct({
  X: CArray(ref.types.uint64, 5),
  Y: CArray(ref.types.uint64, 5),
  Z: CArray(ref.types.uint64, 5),
  T: CArray(ref.types.uint64, 5),
})

const PublicKey = CStruct({
  EdwardsPoint,
  CompressedEdwardsY: CArray(ref.types.uint8, 32),
})

export const Ed25519KeyPair = CStruct({
  public: PublicKey,
  optional: ref.types.uint8,
  secret: CArray(ref.types.uint8, 32),
})
