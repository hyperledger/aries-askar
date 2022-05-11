import { default as array } from 'ref-array-di'
import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)
const CArray = array(ref)

export const Chacha20C20P = CStruct({
  key: CArray(ref.types.uint8, 32),
})
