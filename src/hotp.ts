import { createHmac } from "crypto";

export interface GenerateOptions {
  secret: string;
  counter: number;
  digest?: Buffer;
  digits?: number;
  encoding?: "ascii" | "hex" | "base64";
  algorithm?: "sha1" | "sha256" | "sha512";
}

export interface VerifyOptions extends GenerateOptions {
  token: string;
  window: number;
}

/**
 * Digest the one-time passcode options.
 */
export function digest(options: GenerateOptions): Buffer {
  var i;

  // unpack options
  var secret = options.secret;
  var counter = options.counter;
  var algorithm = (options.algorithm || "sha1").toLowerCase();

  var secret_buffer_size;
  if (algorithm === "sha1") {
    secret_buffer_size = 20; // 20 bytes
  } else if (algorithm === "sha256") {
    secret_buffer_size = 32; // 32 bytes
  } else if (algorithm === "sha512") {
    secret_buffer_size = 64; // 64 bytes
  } else {
    console.warn(
      "Speakeasy - The algorithm provided (`" +
        algorithm +
        "`) is not officially supported, results may be different than expected."
    );
  }

  // The secret for sha1, sha256 and sha512 needs to be a fixed number of bytes for the one-time-password to be calculated correctly
  // Pad the buffer to the correct size be repeating the secret to the desired length
  let secretBuffer: Buffer = Buffer.from(secret);
  if (secret_buffer_size && secret.length !== secret_buffer_size) {
    secretBuffer = new Buffer(
      Array(Math.ceil(secret_buffer_size / secret.length) + 1).join(
        secretBuffer.toString("hex")
      ),
      "hex"
    ).slice(0, secret_buffer_size);
  }

  // create an buffer from the counter
  var buf = new Buffer(8);
  var tmp = counter;
  for (i = 0; i < 8; i++) {
    // mask 0xff over number to get last 8
    buf[7 - i] = tmp & 0xff;

    // shift 8 and get ready to loop over the next batch of 8
    tmp = tmp >> 8;
  }

  // init hmac with the key
  var hmac = createHmac(algorithm, secretBuffer);

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
export function hotpGenerate(options: GenerateOptions): string {
  // verify counter exists
  var counter = options.counter;

  if (counter === null || typeof counter === "undefined") {
    throw new Error("Speakeasy - hotp - Missing counter");
  }

  // unpack options
  const digits = options.digits || 6;

  // digest the options
  let hmacDigest = options.digest || digest(options);

  // compute HOTP offset
  var offset = hmacDigest[hmacDigest.length - 1] & 0xf;

  // calculate binary code (RFC4226 5.4)
  const code =
    ((hmacDigest[offset] & 0x7f) << 24) |
    ((hmacDigest[offset + 1] & 0xff) << 16) |
    ((hmacDigest[offset + 2] & 0xff) << 8) |
    (hmacDigest[offset + 3] & 0xff);

  // left-pad code
  const codeArray = new Array(digits + 1).join("0") + code.toString(10);

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
export function hotpVerifyDelta(options: VerifyOptions): any {
  var i;

  // verify secret and token exist
  var secret = options.secret;
  var token = options.token;
  if (secret === null || typeof secret === "undefined")
    throw new Error("2fa - hotp.verifyDelta - Missing secret");
  if (token === null || typeof token === "undefined")
    throw new Error("2fa - hotp.verifyDelta - Missing token");

  // unpack options
  var token = options.token;
  var digits = options.digits || 6;
  var window = options.window || 0;
  var counter = options.counter || 0;

  // fail if token is not of correct length
  if (token.length !== digits) {
    return;
  }

  // parse token to integer
  const tokenNumber = parseInt(token, 10);

  // fail if token is NA
  if (isNaN(tokenNumber)) {
    return;
  }

  // loop from C to C + W inclusive
  for (i = counter; i <= counter + window; ++i) {
    options.counter = i;
    // domain-specific constant-time comparison for integer codes
    if (parseInt(exports.hotp(options), 10) === tokenNumber) {
      // found a matching code, return delta
      return { delta: i - counter };
    }
  }

  // no codes have matched
}

/**
 * Verify a counter-based one-time token against the secret and return true if
 * it verifies. Helper function for `hotp.verifyDelta()`` that returns a boolean
 * instead of an object. For more on how to use a window with this, see
 * {@link hotp.verifyDelta}.
 */
export function hotpVerify(options: VerifyOptions) {
  return hotpVerifyDelta(options) != null;
}
