export interface HtopGenerateOptions {
  secret: string | Buffer;
  counter: number;
  digest?: Buffer;
  digits?: number;
  encoding?: "ascii" | "hex" | 'base32' | "base64";
  algorithm?: "sha1" | "sha256" | "sha512";
}

export interface HtopVerifyOptions extends HtopGenerateOptions {
  token: string;
  window?: number;
}

export interface VerifyDelta {
  delta: number
}
