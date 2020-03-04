import { hotpGenerate } from "./hotp";

export interface GenerateOptions {
  secret: string;
  time: number;
  step: number;
  epoch: number;
  counter: number;
  digits: number;
  encoding: "ascii" | "hex" | "base64";
  algorithm: "sha1" | "sha256" | "sha512";
};

export interface VerifyOptions extends GenerateOptions{
    token: string
    window: number
};

/**
 * Generate a time-based one-time token. Specify the key, and receive the
 * one-time password for that time as a string. By default, it uses the current
 * time and a time step of 30 seconds, so there is a new token every 30 seconds.
 * You may override the time step and epoch for custom timing. You can also
 * specify a token length, as well as the encoding (ASCII, hexadecimal, or
 * base32) and the hashing algorithm to use (SHA1, SHA256, SHA512).
 *
 * Under the hood, TOTP calculates the counter value by finding how many time
 * steps have passed since the epoch, and calls HOTP with that counter value.
 */
export function totpGenerate(options: GenerateOptions): string {
  // calculate default counter value
  if (options.counter == null) options.counter = exports._counter(options);

  // pass to hotp
  return hotpGenerate(options);
};

/**
 * Verify a time-based one-time token against the secret and return the delta.
 * By default, it verifies the token at the current time window, with no leeway
 * (no look-ahead or look-behind). A token validated at the current time window
 * will have a delta of 0.
 *
 * You can specify a window to add more leeway to the verification process.
 * Setting the window param will check for the token at the given counter value
 * as well as `window` tokens ahead and `window` tokens behind (two-sided
 * window). See param for more info.
 *
 * `verifyDelta()` will return the delta between the counter value of the token
 * and the given counter value. For example, if given a time at counter 1000 and
 * a window of 5, `verifyDelta()` will look at tokens from 995 to 1005,
 * inclusive. In other words, if the time-step is 30 seconds, it will look at
 * tokens from 2.5 minutes ago to 2.5 minutes in the future, inclusive.
 * If it finds it at counter position 1002, it will return `{ delta: 2 }`.
 * If it finds it at counter position 997, it will return `{ delta: -3 }`.
 */
exports.totp.verifyDelta = function totpVerifyDelta(options: VerifyOptions) {
  // shadow options
  options = Object.create(options);
  // verify secret and token exist
  var secret = options.secret;
  var token = options.token;
  if (secret === null || typeof secret === "undefined")
    throw new Error("Speakeasy - totp.verifyDelta - Missing secret");
  if (token === null || typeof token === "undefined")
    throw new Error("Speakeasy - totp.verifyDelta - Missing token");

  // unpack options
  var window = options.window || 0;

  // calculate default counter value
  if (options.counter == null) options.counter = exports._counter(options);

  // adjust for two-sided window
  options.counter -= window;
  options.window += window;

  // pass to hotp.verifyDelta
  var delta = exports.hotp.verifyDelta(options);

  // adjust for two-sided window
  if (delta) {
    delta.delta -= window;
  }

  return delta;
};

/**
 * Verify a time-based one-time token against the secret and return true if it
 * verifies. Helper function for verifyDelta() that returns a boolean instead of
 * an object. For more on how to use a window with this, see
 * {@link totp.verifyDelta}.
 */
export function totpVerify(options: VerifyOptions) {
  return exports.totp.verifyDelta(options) != null;
};
