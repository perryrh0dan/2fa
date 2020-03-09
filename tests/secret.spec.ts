import {generateSecret} from '../src/secret/secret';
import {base32Encode} from '../src/base32';

describe('Generator tests', function() {
  it('Normal generation with defaults', async function() {
    var secret = generateSecret();
    expect(secret.secret.length).toBe(32);
    // const image = await secret.image()
  });

  it('Generation with custom key length', function() {
    var secret = generateSecret({length: 50});
    expect(secret.secret.length).toBe(50);
  });

  it('Generation with symbols disabled', function() {
    var secret = generateSecret({symbols: false});
    expect(/^[a-z0-9]+$/i.test(secret.secret)).toBe(true);
  });

  describe('test otpauth url generation for totp', function() {
    it('should be valid', function() {
      const secret = generateSecret({
        label: 'Example:alice@google.com',
        issuer: 'Example',
      });

      const buf = new Buffer(secret.secret, 'ascii');
      const expectedSecret: string = base32Encode(buf).replace(/=/g, '%3D');

      const expected =
        'otpauth://totp/Example%3Aalice%40google.com?secret=' +
        expectedSecret +
        '&issuer=Example&algorithm=SHA1&digits=6&period=30';
      expect(secret.otpauthURL()).toBe(expected);
    });
  });

  describe('test otpauth url generation for hotp', function() {
    it('should be valid', function() {
      const secret = generateSecret({
        label: 'Example:alice@google.com',
        issuer: 'Example',
      });

      const buf = new Buffer(secret.secret, 'ascii');
      const expectedSecret: string = base32Encode(buf).replace(/=/g, '%3D');

      const expected =
        'otpauth://hotp/Example%3Aalice%40google.com?secret=' +
        expectedSecret +
        '&issuer=Example&counter=1&algorithm=SHA1&digits=6&period=30';
      expect(secret.otpauthURL({type: 'hotp', counter: 1})).toBe(expected);
    });
  });

  describe('test otpauth url generation with missing counter for hotp', function() {
    it('should fail', function() {
      const secret = generateSecret({
        label: 'Example:alice@google.com',
        issuer: 'Example',
      });

      expect(() => {
        secret.otpauthURL({type: 'hotp'});
      }).toThrowError('Missing counter value for HOTP');
    });
  });
});
