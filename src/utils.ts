export function arrayBufferToBuffer(ab: ArrayBuffer): Buffer {
  let buffer = Buffer.alloc(ab.byteLength);
  let view = new Uint8Array(ab);
  for (let i = 0; i < buffer.length; ++i) {
    buffer[i] = view[i];
  }

  return buffer;
}

export function arrayBufferToString(ab: ArrayBuffer): string {
  const buffer = arrayBufferToBuffer(ab);
  return buffer.toString();
}
