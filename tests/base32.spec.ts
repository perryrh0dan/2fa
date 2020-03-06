import { base32Encode, base32Decode } from '../src/base32';
import { arrayBufferToString } from '../src/utils';

describe('base32 tests', function () {
  it('Should encode', function () {
    const base32 = base32Encode(Buffer.from('Test'));
    expect(base32).toBe('KRSXG5A=');
  });

  it('Should encode', function () {
    const arrayBuffer = base32Decode('GEZDGNBVGY3TQOJQ');
    const decoded = arrayBufferToString(arrayBuffer);
    expect(decoded).toBe('1234567890');
  });
});
