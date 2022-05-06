import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

const CStruct = struct(ref)

const LocalKey = (keyType: ref.NamedTypeLike) =>
  CStruct({
    inner: ref.refType(keyType),
    ephemeral: ref.types.bool,
  })

export const LocalKeyHandleStruct = (keyType: ref.NamedTypeLike) => ref.refType(LocalKey(keyType))
