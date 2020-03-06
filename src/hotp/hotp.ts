import { createHmac } from 'crypto';
import { base32Decode } from '../base32';
import { HtopGenerateOptions, HtopVerifyOptions, VerifyDelta } from './types';
import { arrayBufferToBuffer } from '../utils';

/**
 * Digest the one-time passcode options.
 */
export function digest(options: HtopGenerateOptions): Buffer {
  // unpack options
  const secret = options.secret;
  const counter = options.counter;
  const encoding = options.encoding || 'ascii';
  const algorithm = options.algorithm || 'sha1';

  // convert secret to buffer
  let secretBuffer: Buffer;
  if (!Buffer.isBuffer(secret)) {
    if (encoding === 'base32') {
      const arrayBuffer = base32Decode(secret);
      secretBuffer = arrayBufferToBuffer(arrayBuffer);
    } else {
      secretBuffer = Buffer.from(secret, encoding);
    }
  } else {
    secretBuffer = secret;
  }


  let secret_buffer_size;
  if (algorithm === 'sha1') {
    secret_buffer_size = 20; // 20 bytes
  } else if (algorithm === 'sha256') {
    secret_buffer_size = 32; // 32 bytes
  } else if (algorithm === 'sha512') {
    secret_buffer_size = 64; // 64 bytes
  }

  // The secret for sha1, sha256 and sha512 needs to be a fixed number of bytes for the one-time-password to be calculated correctly
  // Pad the buffer to the correct size be repeating the secret to the desired length
  if (secret_buffer_size && secret.length !== secret_buffer_size) {
    secretBuffer = new Buffer(
      Array(Math.ceil(secret_buffer_size / secretBuffer.length) + 1).join(
        secretBuffer.toString('hex')
      ),
      'hex'
    ).slice(0, secret_buffer_size);
  }

  // create an buffer from the counter
  let buf = new Buffer(8);
  let tmp = counter;
  for (let i = 0; i < 8; i++) {
    // mask 0xff over number to get last 8
    buf[7 - i] = tmp & 0xff;

    // shift 8 and get ready to loop over the next batch of 8
    tmp = tmp >> 8;
  }

  // init hmac with the key
  const hmac = createHmac(algorithm, secretBuffer);

  // update hmac with the counter
  hmac.update(buf);

  // return the digest
  return hmac.digest();
}

/**
 * Generate a counter-based one-time token. Specify the key and counter, and
 * receive the one-time password for that counter position as a string. You can
 * also specify a token length, as well as the encoding (ASCII, hexadecimal, or
 * base32) and the hashing algorithm to use (SHA1, SHA256, SHA512).
 */
export function hotpGenerate(options: HtopGenerateOptions): string {
  // unpack options
  const digits = options.digits || 6;

  // digest the options
  const hmacDigest = options.digest || digest(options);

  // compute HOTP offset
  const offset = hmacDigest[hmacDigest.length - 1] & 0xf;

  // calculate binary code (RFC4226 5.4)
  const code =
    ((hmacDigest[offset] & 0x7f) << 24) |
    ((hmacDigest[offset + 1] & 0xff) << 16) |
    ((hmacDigest[offset + 2] & 0xff) << 8) |
    (hmacDigest[offset + 3] & 0xff);

  // left-pad code
  const codeArray = new Array(digits + 1).join('0') + code.toString(10);

  // return length number off digits
  return codeArray.substr(-digits);
}

/**
 * Verify a counter-based one-time token against the secret and return the delta.
 * By default, it verifies the token at the given counter value, with no leeway
 * (no look-ahead or look-behind). A token validated at the current counter value
 * will have a delta of 0.
 *
 * You can specify a window to add more leeway to the verification process.
 * Setting the window param will check for the token at the given counter value
 * as well as `window` tokens ahead (one-sided window). See param for more info.
 *
 * `verifyDelta()` will return the delta between the counter value of the token
 * and the given counter value. For example, if given a counter 5 and a window
 * 10, `verifyDelta()` will look at tokens from 5 to 15, inclusive. If it finds
 * it at counter position 7, it will return `{ delta: 2 }`.
 */
export function hotpVerifyDelta(options: HtopVerifyOptions): VerifyDelta {
  // verify secret and token exist
  var secret = options.secret;
  var token = options.token;
  if (secret === null || typeof secret === 'undefined')
    throw new Error('2fa - hotp.verifyDelta - Missing secret');
  if (token === null || typeof token === 'undefined')
    throw new Error('2fa - hotp.verifyDelta - Missing token');

  // unpack options
  var token = options.token;
  var digits = options.digits || 6;
  var window = options.window || 0;
  var counter = options.counter || 0;

  // fail if token is not of correct length
  if (token.length !== digits) {
    throw new Error('Wrong token length');
  }

  // parse token to integer
  const tokenNumber = parseInt(token, 10);

  // fail if token is NA
  if (isNaN(tokenNumber)) {
    throw new Error('Cant parse token to number');
  }

  // loop from C to C + W inclusive
  for (let i = counter; i <= counter + window; ++i) {
    options.counter = i;
    // domain-specific constant-time comparison for integer codes
    if (parseInt(hotpGenerate(options), 10) === tokenNumber) {
      // found a matching code, return delta
      return { delta: i - counter };
    }
  }

  throw new Error('No matching code found');
}

/**
 * Verify a counter-based one-time token against the secret and return true if
 * it verifies. Helper function for `hotp.verifyDelta()`` that returns a boolean
 * instead of an object. For more on how to use a window with this, see
 * {@link hotp.verifyDelta}.
 */
export function hotpVerify(options: HtopVerifyOptions): boolean {
  try {
    return hotpVerifyDelta(options) != null;
  } catch (error) {
    return false;
  }
}
