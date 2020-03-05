const RFC4648 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface Base32EncodeOptions {
  padding: boolean;
}

export function base32Encode(
  buffer: ArrayBuffer,
  options: Partial<Base32EncodeOptions> = {},
): string {
  let alphabet: string;
  let defaultPadding: boolean;

  alphabet = RFC4648;
  defaultPadding = true;

  const padding = options.padding === undefined ? defaultPadding : options.padding;
  const length = buffer.byteLength;
  const view = new Uint8Array(buffer);

  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < length; i++) {
    value = (value << 8) | view[i];
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  if (padding) {
    while (output.length % 8 !== 0) {
      output += '=';
    }
  }

  return output;
}

function readChar(alphabet: string, char: string): number {
  const idx = alphabet.indexOf(char);

  if (idx === -1) {
    throw new Error('Invalid character found: ' + char);
  }

  return idx;
}

export function base32Decode(input: string): ArrayBuffer {
  let alphabet: string;
  let cleanedInput: string;

  alphabet = RFC4648;
  cleanedInput = input.toUpperCase().replace(/\=+$/, '');

  const { length } = cleanedInput;

  let bits = 0;
  let value = 0;

  let index = 0;
  const output = new Uint8Array(((length * 5) / 8) | 0);

  for (let i = 0; i < length; i++) {
    value = (value << 5) | readChar(alphabet, cleanedInput[i]);
    bits += 5;

    if (bits >= 8) {
      output[index++] = (value >>> (bits - 8)) & 255;
      bits -= 8;
    }
  }

  return output.buffer;
}
