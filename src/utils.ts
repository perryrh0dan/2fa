var base32 = require('base32.js');
import * as base32Encode from 'base32-encode'
import { randomBytes } from 'crypto';
import { create, toString } from 'qrcode';
import { format } from 'url';

export interface GenerateOptions {
  length?: number
  symbols?: boolean
  name?: string
  issuer?: string
}

export class SecretKey {
  private _secret: string
  private _name: string
  private _issuer: string

  constructor(secret: string, name: string, issuer: string) {
    this._secret = secret;
    this._name = name;
    this._issuer = issuer;
  }

  get secret(): string {
    return this._secret
  }

  get name() {
    return this._name
  }

  get issuer() {
    return this._issuer
  }

  public async image(): Promise<string> {
    const qrcode = create(this._secret, {})
    return toString(qrcode.segments)
  }
}

/**
 * Generates a random secret with the set A-Z a-z 0-9 and symbols, of any length
 * (default 32). Returns the secret key in ASCII, hexadecimal, and base32 format,
 * along with the URL used for the QR code for Google Authenticator (an otpauth
 * URL). Use a QR code library to generate a QR code based on the Google
 * Authenticator URL to obtain a QR code you can scan into the app.
 */
export function generateSecret(options?: GenerateOptions) {
  // options
  if (!options) options = {};
  const length = options.length || 32;
  const symbols = options.symbols || false;
  const name = options.name || 'SecretKey';
  const issuer = options.issuer || '';

  // generate an ascii key
  var key = generateSecretASCII(length, symbols);

  // return a SecretKey with ascii, hex, and base32
  var secretKey: SecretKey = new SecretKey(key, name, issuer);

  return secretKey;
};

/**
 * Generates a key of a certain length (default 32) from A-Z, a-z, 0-9, and
 * symbols (if requested).
 */
export function generateSecretASCII(length?: number, symbols?: boolean): string {
  var bytes = randomBytes(length || 32);
  var set = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz';
  if (symbols) {
    set += '!@#$%^&*()<>?/[]{},.:;';
  }

  var output = '';
  for (var i = 0, l = bytes.length; i < l; i++) {
    output += set[Math.floor(bytes[i] / 255.0 * (set.length - 1))];
  }
  return output;
};

export function otpauthURL (options) {
  // unpack options
  var secret = options.secret;
  var label = options.label;
  var issuer = options.issuer;
  var type = (options.type || 'totp').toLowerCase();
  var counter = options.counter;
  var algorithm = (options.algorithm || 'sha1').toLowerCase();
  var digits = options.digits || 6;
  var period = options.period || 30;
  var encoding = options.encoding || 'ascii';

  // validate type
  switch (type) {
    case 'totp':
    case 'hotp':
      break;
    default:
      throw new Error('Speakeasy - otpauthURL - Invalid type `' + type + '`; must be `hotp` or `totp`');
  }

  // validate required options
  if (!secret) throw new Error('Speakeasy - otpauthURL - Missing secret');
  if (!label) throw new Error('Speakeasy - otpauthURL - Missing label');

  // require counter for HOTP
  if (type === 'hotp' && (counter === null || typeof counter === 'undefined')) {
    throw new Error('Speakeasy - otpauthURL - Missing counter value for HOTP');
  }

  // convert secret to base32
  if (encoding !== 'base32') secret = new Buffer(secret, encoding);
  if (Buffer.isBuffer(secret)) secret = base32.encode(secret);

  // build query while validating
  var query = {secret: secret};
  if (issuer) query.issuer = issuer;
  if (type === 'hotp') {
    query.counter = counter;
  }

  // validate algorithm
  if (algorithm != null) {
    switch (algorithm.toUpperCase()) {
      case 'SHA1':
      case 'SHA256':
      case 'SHA512':
        break;
      default:
        console.warn('Speakeasy - otpauthURL - Warning - Algorithm generally should be SHA1, SHA256, or SHA512');
    }
    query.algorithm = algorithm.toUpperCase();
  }

  // validate digits
  if (digits != null) {
    if (isNaN(digits)) {
      throw new Error('Speakeasy - otpauthURL - Invalid digits `' + digits + '`');
    } else {
      switch (parseInt(digits, 10)) {
        case 6:
        case 8:
          break;
        default:
          console.warn('Speakeasy - otpauthURL - Warning - Digits generally should be either 6 or 8');
      }
    }
    query.digits = digits;
  }

  // validate period
  if (period != null) {
    period = parseInt(period, 10);
    if (~~period !== period) {
      throw new Error('Speakeasy - otpauthURL - Invalid period `' + period + '`');
    }
    query.period = period;
  }

  // return url
  return format({
    protocol: 'otpauth',
    slashes: true,
    hostname: type,
    pathname: encodeURIComponent(label),
    query: query
  });
};
