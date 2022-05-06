import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

const ArrayKey = (len = 32) =>
  CStruct({
    GenericArray: CArray(ref.types.uint8, len),
  })

export const Chacha20Key = CStruct({
  alg: ref.types.CString,
  key: ArrayKey(),
})
