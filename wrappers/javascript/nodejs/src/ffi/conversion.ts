/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/no-unsafe-argument */
import type { EncryptedBufferType } from './structures'
import type { TypedArray } from 'ref-array-di'
import type { Pointer } from 'ref-napi'

import { ByteBuffer, EncryptedBuffer } from 'aries-askar-shared'
import { reinterpret } from 'ref-napi'

import { ByteBufferStruct } from './structures'

// TODO: Does this do correct conversion? The data -> pointer scenario
export const byteBufferClassToStruct = ({ len, data }: ByteBuffer) => {
  return ByteBufferStruct({
    len,
    data: Buffer.from(data) as Pointer<TypedArray<number, number>>,
  })
}

export const byteBufferToReference = (byteBuffer: ByteBufferType) => {
  throw AriesAskarError.customError({ message: 'Method byteBufferToReference not implemented' })
}

export const secretBufferClassToStruct = byteBufferClassToStruct

export const uint8arrayToByteBufferStruct = (buf: Uint8Array) => {
  const byteBuffer = ByteBuffer.fromUint8Array(buf)
  return byteBufferClassToStruct(byteBuffer)
}

export const byteBufferToBuffer = (buffer: { data: Buffer; len: number }) => reinterpret(buffer.data, buffer.len)

export const secretBufferToBuffer = byteBufferToBuffer

export const encryptedBufferStructToClass = (encryptedBuffer: EncryptedBufferType) => {
  // @ts-ignore
  const buffer = Uint8Array.from(secretBufferToBuffer(encryptedBuffer.secretBuffer))
  // @ts-ignore
  const noncePos = encryptedBuffer.nonce_pos
  // @ts-ignore
  const tagPos = encryptedBuffer.tag_pos

  return new EncryptedBuffer({ tagPos, noncePos, buffer })
}
