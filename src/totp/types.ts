export interface TotpGenerateOptions {
  secret: string | Buffer;
  time?: number;
  step?: number;
  epoch?: number;
  counter?: number;
  digits?: number;
  encoding?: "ascii" | "hex" | 'base32' | "base64";
  algorithm?: "sha1" | "sha256" | "sha512";
};

export interface CounterOptions {
  time?: number
  step?: number
  epoch?: number
}

export interface VerifyOptions extends TotpGenerateOptions{
    token: string
    window?: number
};
