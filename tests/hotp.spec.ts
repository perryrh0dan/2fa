import { hotpGenerate } from '../src/hotp/hotp';

describe('HOTP Counter-Based Algorithm Test', function () {
  describe('normal operation with secret = "12345678901234567890" at counter 3', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: '12345678901234567890',
        counter: 3
      });
      expect(topic).toBe('969429');
    });
  });

  describe('another counter normal operation with secret = "12345678901234567890" at counter 7', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: '12345678901234567890',
        counter: 7
      });
      expect(topic).toBe('162583');
    });
  });

  describe('digits override with secret = "12345678901234567890" at counter 4 and digits = 8', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: '12345678901234567890',
        counter: 4,
        digits: 8
      });
      expect(topic).toBe('40338314');
    });
  });

  describe('hexadecimal encoding with secret = "3132333435363738393031323334353637383930" as hexadecimal at counter 4', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: '3132333435363738393031323334353637383930',
        encoding: 'hex',
        counter: 4
      });
      expect(topic).toBe('338314');
    });
  });

  describe('base32 encoding with secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" as base32 at counter 4', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
        encoding: 'base32',
        counter: 4
      });
      expect(topic).toBe('338314');
    });
  });

  describe('base32 encoding with secret = "12345678901234567890" at counter 3', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: '12345678901234567890',
        counter: 3
      });
      expect(topic).toBe('969429');
    });
  });

  describe('base32 encoding with secret = "GEZDGNBVGY3TQOJQ" as base32 at counter 1, digits = 8 and algorithm as "sha256"', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: 'GEZDGNBVGY3TQOJQ',
        encoding: 'base32',
        counter: 1,
        digits: 8,
        algorithm: 'sha256'
      });
      expect(topic).toBe('46119246');
    });
  });

  describe('base32 encoding with secret = "GEZDGNBVGY3TQOJQ" as base32 at counter 1, digits = 8 and algorithm as "sha512"', function () {
    it('should return correct one-time password', function () {
      const topic = hotpGenerate({
        secret: 'GEZDGNBVGY3TQOJQ',
        encoding: 'base32',
        counter: 1,
        digits: 8,
        algorithm: 'sha512'
      });
      expect(topic).toBe('90693936');
    });
  });
});
