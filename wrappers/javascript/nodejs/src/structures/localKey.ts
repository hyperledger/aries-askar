import type { ILocalKeyHandle, KeyAlgs } from 'aries-askar-shared'

import * as ref from 'ref-napi'
import { default as struct } from 'ref-struct-di'

type LocalKeyHandleOptions<K = Record<string, unknown>> = {
  alg: KeyAlgs
  inner: K
  ephemeral: boolean
}

const CStruct = struct(ref)

const LocalKey = (keyType: ref.NamedTypeLike) =>
  CStruct({
    inner: ref.refType(keyType),
    ephemeral: ref.types.bool,
  })

export const LocalKeyHandleStruct = (keyType: ref.NamedTypeLike) => ref.refType(LocalKey(keyType))

export type LocalKeyHandleType<T = unknown> = struct.StructObject<{
  inner: ref.Pointer<T>
  ephemeral: boolean
}>

export class LocalKeyHandle<K = Record<string, unknown>> implements ILocalKeyHandle<K> {
  public alg: KeyAlgs
  public inner: K
  public ephemeral: boolean
  public bufRep: Buffer
  public constructor({ ephemeral, inner, alg, bufRep }: LocalKeyHandleOptions<K> & { bufRep: Buffer }) {
    this.bufRep = bufRep
    this.alg = alg
    this.inner = inner
    this.ephemeral = ephemeral
  }
}
