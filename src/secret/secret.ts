import { randomBytes } from 'crypto';
import { create, toString } from 'qrcode';
import { format } from 'url';
import { base32Encode } from '../base32';
import { ImageOptions, Query, SecretOptions } from './types';

export class SecretKey {
  private _secret: string
  private _label: string
  private _issuer: string

  public constructor(secret: string, label: string, issuer: string) {
    this._secret = secret;
    this._label = label;
    this._issuer = issuer;
  }

  public get secret(): string {
    return this._secret;
  }

  public get label(): string {
    return this._label;
  }

  public get issuer(): string {
    return this._issuer;
  }

  public async image(options?: ImageOptions): Promise<string> {
    const otpauthURL = this.otpauthURL(options);
    const qrcode = create(otpauthURL, {});
    return toString(qrcode.segments);
  }

  /**
   * Generate a Google Authenticator-compatible otpauth:// URL for passing the
   * secret to a mobile device to install the secret.
   *
   * Authenticator considers TOTP codes valid for 30 seconds. Additionally,
   * the app presents 6 digits codes to the user. According to the
   * documentation, the period and number of digits are currently ignored by
   * the app.
   *
   * To generate a suitable QR Code, pass the generated URL to a QR Code
   * generator, such as the `qr-image` module.
   */
  public otpauthURL(options?: ImageOptions): string {
    // unpack options
    if (!options) options = {};
    var secret = this.secret;
    var label = this.label;
    var issuer = this.issuer;
    var type = options.type || 'totp';
    var algorithm = options.algorithm || 'sha1';
    var digits = options.digits || 6;
    var period = options.period || 30;
    var encoding = options.encoding || 'ascii';

    // require counter for HOTP
    if (type === 'hotp' && typeof options.counter === 'undefined') {
      throw new Error('Speakeasy - otpauthURL - Missing counter value for HOTP');
    }

    var counter = options.counter;

    // convert secret to base32
    if (encoding !== 'base32') {
      const buffer = Buffer.from(secret, encoding);
      secret = base32Encode(buffer);
    }

    // build query while validating
    const query: Query = { secret: secret };

    if (issuer) query.issuer = issuer;
    if (type === 'hotp') {
      query.counter = counter;
    }

    query.algorithm = algorithm.toUpperCase();

    // validate digits
    switch (digits) {
      case 6:
      case 8:
        break;
      default:
        console.warn('Speakeasy - otpauthURL - Warning - Digits generally should be either 6 or 8');
    }
    query.digits = digits;
    query.period = period;

    // return url
    return format({
      protocol: 'otpauth',
      slashes: true,
      hostname: type,
      pathname: encodeURIComponent(label),
      query: query
    });
  };
}

/**
 * Generates a random secret with the set A-Z a-z 0-9 and symbols, of any length
 * (default 32). Returns the secret key in ASCII, hexadecimal, and base32 format,
 * along with the URL used for the QR code for Google Authenticator (an otpauth
 * URL). Use a QR code library to generate a QR code based on the Google
 * Authenticator URL to obtain a QR code you can scan into the app.
 */
export function generateSecret(options?: SecretOptions): SecretKey {
  // options
  if (!options) options = {};
  const length = options.length || 32;
  const symbols = options.symbols || false;
  const label = options.label || 'SecretKey';
  const issuer = options.issuer || '';

  // generate an ascii key
  var key = generateSecretASCII(length, symbols);

  // return a SecretKey with ascii, hex, and base32
  var secretKey: SecretKey = new SecretKey(key, label, issuer);

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
