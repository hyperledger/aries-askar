/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable @typescript-eslint/ban-ts-comment */
/* eslint-disable @typescript-eslint/no-unsafe-call */
/* eslint-disable @typescript-eslint/no-unsafe-member-access */
type JwkProps = {
  kty: string
  crv: string
  x: string
  d: string
}

export class Jwk {
  public kty: string
  public crv: string
  public x: string
  public d: string

  public constructor({ kty, crv, x, d }: JwkProps) {
    this.kty = kty
    this.crv = crv
    this.x = x
    this.d = d
  }

  public static fromJson(jwk: JwkProps) {
    return new Jwk(jwk)
  }

  public static fromString(str: string) {
    return new Jwk(JSON.parse(str) as JwkProps)
  }

  public toUint8Array() {
    // @ts-ignore
    const encoder = new TextEncoder()
    const encoded = encoder.encode(JSON.stringify({ kty: this.kty, crv: this.crv, x: this.x, d: this.d })) as Uint8Array
    return encoded
  }
}
