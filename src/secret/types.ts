export interface SecretOptions {
  length?: number
  symbols?: boolean
  label?: string
  issuer?: string
}

export interface ImageOptions{
  type?: 'totp' | 'hotp'
  counter?: number
  algorithm?: 'sha1' | 'sha256' | 'sha512'
  digits?: number
  period?: number
  encoding?: 'ascii' | 'hex' | 'base32' | 'base64'
}

export type Query = {
  secret: string
  issuer?: string
  counter?: number
  algorithm?: string
  digits?: number
  period?: number
}
