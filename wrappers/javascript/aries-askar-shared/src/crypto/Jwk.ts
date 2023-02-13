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
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
    const encoder = new TextEncoder()
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    const encoded = encoder.encode(JSON.stringify(this)) as Uint8Array
    return encoded
  }
}
