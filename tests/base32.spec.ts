import {base32Encode, base32Decode} from '../src/base32';
import {arrayBufferToString} from '../src/utils';

describe('base32 tests', function() {
  describe('encoding with default options', function() {
    it('should encode', function() {
      const base32 = base32Encode(Buffer.from('Test'));
      expect(base32).toBe('KRSXG5A=');
    });
  });

  describe('decoding with default options', function() {
    it('Should decode', function() {
      const arrayBuffer = base32Decode('GEZDGNBVGY3TQOJQ');
      const decoded = arrayBufferToString(arrayBuffer);
      expect(decoded).toBe('1234567890');
    });
  });

  describe('test encoding with padding = false', function() {
    it('should encode', function() {
      const base32 = base32Encode(Buffer.from('Testtd'), { padding: false });
      expect(base32).toBe('KRSXG5DUMQ');
    });
  });

  describe('test decode with wrong charset', function() {
    it('should throw error', function() {
      expect(() => {
        base32Decode('GEZDGNBVGY3TQOJQ§');
      }).toThrowError('Invalid character found: §');
    });
  });
});
