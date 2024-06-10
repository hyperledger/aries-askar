import { Buffer } from 'buffer'

export type JwkProps = {
  kty: string
  crv: string
  x: string
  d?: string
  y?: string
}

export class Jwk {
  public kty: string
  public crv: string
  public x: string
  public d?: string
  public y?: string

  public constructor({ kty, crv, x, d, y }: JwkProps) {
    this.kty = kty
    this.crv = crv
    this.x = x
    this.d = d
    this.y = y
  }

  public static fromJson(jwk: JwkProps) {
    return new Jwk(jwk)
  }

  public static fromString(str: string) {
    return new Jwk(JSON.parse(str) as JwkProps)
  }

  public toUint8Array() {
    return Uint8Array.from(Buffer.from(JSON.stringify(this)))
  }
}
