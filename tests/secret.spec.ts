import {generateSecret} from '../src/secret/secret';
import {base32Encode} from '../src/base32';

describe('Test secret generation', function() {
  describe('with default options', function() {
    it('should be of length 32', async function() {
      var secret = generateSecret({ label: 'exampleName', issuer: 'exampleIssuer'});
      expect(secret.secret.length).toBe(32);
      // const image = await secret.image()
    });
  });
  
  describe('with length = 50', function() {
    it('should generation with symbols disabled', function() {
      var secret = generateSecret({label: 'exampleName', issuer: 'exampleIssuer', length: 50});
      expect(secret.secret.length).toBe(50);
    });
  });
  
  describe('with symbols = true', function() {
    it('should generation with symbols enabled', function() {
      var secret = generateSecret({label: 'exampleName', issuer: 'exampleIssuer', symbols: true});
      expect(/^[a-z0-9!@#$%^&*()<>?/[\]{},.:;]+$/i.test(secret.secret)).toBe(true);
    });
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