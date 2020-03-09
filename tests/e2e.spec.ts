import { generateSecret } from '../src/secret';
import { totpGenerate, totpVerify } from '../src/totp';
import { hotpGenerate, hotpVerify } from '../src/hotp';

describe('Test totp in end to end scenario', function () {
  describe('with default options', function() {
    it('should be valid', function () {
      const secret = generateSecret({
        label: 'accountName',
        issuer: 'issuerName',
      });
      const code = totpGenerate({ secret: secret.secret });
      const valid = totpVerify({ secret: secret.secret, token: code });
  
      expect(valid).toBe(true);
    });
  });
  
  describe('with window = -1 only for validation', function() {
    it('should be invalid', function () {
      const secret = generateSecret({
        label: 'accountName',
        issuer: 'issuerName',
      });
      const code = totpGenerate({ secret: secret.secret });
      const valid = totpVerify({
        secret: secret.secret,
        token: code,
        window: -1,
      });
  
      expect(valid).toBe(false);
    });
  });
});

describe('Test hotp in end to end scenarios', function () {
  describe('Code generated with counter = 1 should be valid for counter = 1', function () {
    it('should be valid', function () {
      const secret = generateSecret({
        label: 'admin',
        issuer: 'tpoe.dev',
      });
      const code = hotpGenerate({ secret: secret.secret, counter: 1 });
      const valid = hotpVerify({
        secret: secret.secret,
        counter: 1,
        token: code,
      });

      expect(valid).toBe(true);
    });
  });

  describe('Code generated with counter = 3 should be valid for counter = 1 and window = 2', function () {
    it('should be valid', function () {
      const secret = generateSecret({
        label: 'admin',
        issuer: 'tpoe.dev',
      });
      const code = hotpGenerate({ secret: secret.secret, counter: 3 });
      const valid = hotpVerify({
        secret: secret.secret,
        token: code,
        counter: 1,
        window: 2,
      });

      expect(valid).toBe(true);
    });
  });

  describe('code generated with counter = 3 should be invalid for counter = 1 and window = 1', function () {
    it('should be invalid', function () {
      const secret = generateSecret({
        label: 'admin',
        issuer: 'tpoe.dev',
      });
      const code = hotpGenerate({ secret: secret.secret, counter: 3 });
      const valid = hotpVerify({
        secret: secret.secret,
        token: code,
        counter: 1,
        window: 1,
      });

      expect(valid).toBe(false);
    });
  });
});
