'use strict';

import { randomBytes } from 'crypto'
var url = require('url');

/**
 * Calculate counter value based on given options. A counter value converts a
 * TOTP time into a counter value by finding the number of time steps that have
 * passed since the epoch to the current time.
 *
 * @param {Object} options
 * @param {Integer} [options.time] Time in seconds with which to calculate
 *   counter value. Defaults to `Date.now()`.
 * @param {Integer} [options.step=30] Time step in seconds
 * @param {Integer} [options.epoch=0] Initial time since the UNIX epoch from
 *   which to calculate the counter value. Defaults to 0 (no offset).
 * @param {Integer} [options.initial_time=0] (DEPRECATED. Use `epoch` instead.)
 *   Initial time in seconds since the UNIX epoch from which to calculate the
 *   counter value. Defaults to 0 (no offset).
 * @return {Integer} The calculated counter value.
 * @private
 */

exports._counter = function _counter (options) {
  var step = options.step || 30;
  var time = options.time != null ? (options.time * 1000) : Date.now();

  // also accepts 'initial_time', but deprecated
  var epoch = (options.epoch != null ? (options.epoch * 1000) : (options.initial_time * 1000)) || 0;
  if (options.initial_time != null) console.warn('Speakeasy - Deprecation Notice - Specifying the epoch using `initial_time` is no longer supported. Use `epoch` instead.');

  return Math.floor((time - epoch) / step / 1000);
};

/**
 * @typedef GeneratedSecret
 * @type Object
 * @property {String} ascii ASCII representation of the secret
 * @property {String} hex Hex representation of the secret
 * @property {String} base32 Base32 representation of the secret
 * @property {String} qr_code_ascii URL for the QR code for the ASCII secret.
 * @property {String} qr_code_hex URL for the QR code for the hex secret.
 * @property {String} qr_code_base32 URL for the QR code for the base32 secret.
 * @property {String} google_auth_qr URL for the Google Authenticator otpauth
 *   URL's QR code.
 * @property {String} otpauth_url Google Authenticator-compatible otpauth URL.
 */

/**
 * Generates a random secret with the set A-Z a-z 0-9 and symbols, of any length
 * (default 32). Returns the secret key in ASCII, hexadecimal, and base32 format,
 * along with the URL used for the QR code for Google Authenticator (an otpauth
 * URL). Use a QR code library to generate a QR code based on the Google
 * Authenticator URL to obtain a QR code you can scan into the app.
 *
 * @param {Object} options
 * @param {Integer} [options.length=32] Length of the secret
 * @param {Boolean} [options.symbols=false] Whether to include symbols
 * @param {Boolean} [options.otpauth_url=true] Whether to output a Google
 *   Authenticator-compatible otpauth:// URL (only returns otpauth:// URL, no
 *   QR code)
 * @param {String} [options.name] The name to use with Google Authenticator.
 * @param {Boolean} [options.qr_codes=false] (DEPRECATED. Do not use to prevent
 *   leaking of secret to a third party. Use your own QR code implementation.)
 *   Output QR code URLs for the token.
 * @param {Boolean} [options.google_auth_qr=false] (DEPRECATED. Do not use to
 *   prevent leaking of secret to a third party. Use your own QR code
 *   implementation.) Output a Google Authenticator otpauth:// QR code URL.
 * @param {String} [options.issuer=''] The provider or service with which the
 *   secret key is associated.
 * @return {Object}
 * @return {GeneratedSecret} The generated secret key.
 */
exports.generateSecret = function generateSecret (options) {
  // options
  if (!options) options = {};
  var length = options.length || 32;
  var name = options.name || 'SecretKey';
  var qr_codes = options.qr_codes || false;
  var google_auth_qr = options.google_auth_qr || false;
  var otpauth_url = options.otpauth_url != null ? options.otpauth_url : true;
  var symbols = true;
  var issuer = options.issuer;

  // turn off symbols only when explicity told to
  if (options.symbols !== undefined && options.symbols === false) {
    symbols = false;
  }

  // generate an ascii key
  var key = this.generateSecretASCII(length, symbols);

  // return a SecretKey with ascii, hex, and base32
  var SecretKey = {};
  SecretKey.ascii = key;
  SecretKey.hex = Buffer(key, 'ascii').toString('hex');
  SecretKey.base32 = base32.encode(Buffer(key)).toString().replace(/=/g, '');

  // add in the Google Authenticator-compatible otpauth URL
  if (otpauth_url) {
    SecretKey.otpauth_url = exports.otpauthURL({
      secret: SecretKey.ascii,
      label: name,
      issuer: issuer
    });
  }

  return SecretKey;
};

/**
 * Generates a key of a certain length (default 32) from A-Z, a-z, 0-9, and
 * symbols (if requested).
 *
 * @param  {Integer} [length=32]  The length of the key.
 * @param  {Boolean} [symbols=false] Whether to include symbols in the key.
 * @return {String} The generated key.
 */
exports.generateSecretASCII = function generateSecretASCII (length, symbols) {
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
 *
 * @param {Object} options
 * @param {String} options.secret Shared secret key
 * @param {String} options.label Used to identify the account with which
 *   the secret key is associated, e.g. the user's email address.
 * @param {String} [options.type="totp"] Either "hotp" or "totp".
 * @param {Integer} [options.counter] The initial counter value, required
 *   for HOTP.
 * @param {String} [options.issuer] The provider or service with which the
 *   secret key is associated.
 * @param {String} [options.algorithm="sha1"] Hash algorithm (sha1, sha256,
 *   sha512).
 * @param {Integer} [options.digits=6] The number of digits for the one-time
 *   passcode. Currently ignored by Google Authenticator.
 * @param {Integer} [options.period=30] The length of time for which a TOTP
 *   code will be valid, in seconds. Currently ignored by Google
 *   Authenticator.
 * @param {String} [options.encoding] Key encoding (ascii, hex, base32,
 *   base64). If the key is not encoded in Base-32, it will be reencoded.
 * @return {String} A URL suitable for use with the Google Authenticator.
 * @throws Error if secret or label is missing, or if hotp is used and a
    counter is missing, if the type is not one of `hotp` or `totp`, if the
    number of digits is non-numeric, or an invalid period is used. Warns if
    the number of digits is not either 6 or 8 (though 6 is the only one
    supported by Google Authenticator), and if the hashihng algorithm is
    not one of the supported SHA1, SHA256, or SHA512.
 * @see https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 */

exports.otpauthURL = function otpauthURL (options) {
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
  return url.format({
    protocol: 'otpauth',
    slashes: true,
    hostname: type,
    pathname: encodeURIComponent(label),
    query: query
  });
};