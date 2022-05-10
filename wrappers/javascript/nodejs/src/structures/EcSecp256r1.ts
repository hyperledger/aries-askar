import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

const AffinePoint = CStruct({
  x: CArray(ref.types.uint64, 4),
  y: CArray(ref.types.uint64, 4),
  infintiy: ref.types.uint8,
})

const PublicKey = CStruct({
  point: AffinePoint,
})

export const EcSecp256r1 = CStruct({
  optional: ref.types.uint8,
  secret: CArray(ref.types.uint64, 4),
  public: PublicKey,
})
