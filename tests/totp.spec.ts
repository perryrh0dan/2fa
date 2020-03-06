import { totpGenerate, totpVerifyDelta } from '../src/totp';

describe('TOTP Time-Based Algorithm Test', function () {
  describe('normal operation with secret = "12345678901234567890" at time = 59', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '12345678901234567890', time: 59 });
      expect(topic).toBe('287082');
    });
  });

  describe('a different time normal operation with secret = "12345678901234567890" at time = 1111111109', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '12345678901234567890', time: 1111111109 });
      expect(topic).toBe('081804');
    });
  });

  describe('digits parameter with secret = "12345678901234567890" at time = 1111111109 and digits = 8', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '12345678901234567890', time: 1111111109, digits: 8 });
      expect(topic).toBe('07081804');
    });
  });

  describe('hexadecimal encoding with secret = "3132333435363738393031323334353637383930" as hexadecimal at time 1111111109', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '3132333435363738393031323334353637383930', encoding: 'hex', time: 1111111109 });
      expect(topic).toBe('081804');
    });
  });

  describe('base32 encoding with secret = "1234567890" at time = 1111111109', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '12345678901234567890', time: 1111111109 });
      expect(topic).toBe('081804');
    });
  });

  describe('base32 encoding with secret = "GEZDGNBVGY3TQOJQ" as base32 at time = 1111111109, digits = 8 and algorithm as "sha256"', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: 'GEZDGNBVGY3TQOJQ', encoding: 'base32', time: 1111111109, digits: 8, algorithm: 'sha256' });
      expect(topic).toBe('68084774');
    });
  });

  describe('base32 encoding with secret = "GEZDGNBVGY3TQOJQ" as base32 at time = 1111111109, digits = 8 and algorithm as "sha512"', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: 'GEZDGNBVGY3TQOJQ', encoding: 'base32', time: 1111111109, digits: 8, algorithm: 'sha512' });
      expect(topic).toBe('25091201');
    });
  });

  describe('normal operation with secret = "12345678901234567890" with overridden counter 3', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '12345678901234567890', counter: 3 });
      expect(topic).toBe('969429');
    });
  });

  describe('normal operation with secret = "12345678901234567890" with overridden counter 3', function () {
    it('should return correct one-time password', function () {
      const topic = totpGenerate({ secret: '12345678901234567890', counter: 3 });
      expect(topic).toBe('969429');
    });
  });

  describe('totpVerifyDelta() window tests', function () {
    const secret = 'rNONHRni6BAk7y2TiKrv';
    it('should get current TOTP value', function () {
      const token = totpGenerate({ secret: secret, counter: 1 });
      expect(token).toBe('314097');
    });

    it('should get TOTP value at counter 3', function () {
      const token = totpGenerate({ secret: secret, counter: 3 });
      expect(token).toBe('663640');
    });

    it('should get delta with varying window lengths', function () {
      let delta = totpVerifyDelta({
        secret: secret, token: '314097', counter: 1, window: 0
      });
      expect(delta.delta).toStrictEqual(0);

      delta = totpVerifyDelta({
        secret: secret, token: '314097', counter: 1, window: 2
      });
      expect(delta.delta).toStrictEqual(0);

      delta = totpVerifyDelta({
        secret: secret, token: '314097', counter: 1, window: 3
      });
      expect(delta.delta).toStrictEqual(0);
    });

    it('should get delta when the item is not at specified counter but within window', function () {
      // Use token at counter 3, initial counter 1, and a window of 2
      let delta = totpVerifyDelta({
        secret: secret, token: '663640', counter: 1, window: 2
      });
      expect(delta.delta).toStrictEqual(2);
    });

    it('should not get delta when the item is not at specified counter and not within window', function () {
      // Use token at counter 3, initial counter 1, and a window of 1
      expect(() => {
        totpVerifyDelta({
          secret: secret, token: '663640', counter: 1, window: 1
        });
      }).toThrow('No matching code found');
    });

    it('should support negative delta values when token is on the negative side of the window', function () {
      // Use token at counter 1, initial counter 3, and a window of 2
      let delta = totpVerifyDelta({
        secret: secret, token: '314097', counter: 3, window: 2
      });
      expect(delta.delta).toStrictEqual(-2);
    });

    it('should support negative delta values when token is on the negative side of the window using time input', function () {
      // Use token at counter 1, initial counter 3, and a window of 2
      let delta = totpVerifyDelta({
        secret: secret, token: '625175', time: 1453854005, window: 2
      });
      expect(delta.delta).toStrictEqual(-2);
    });
  });
});
