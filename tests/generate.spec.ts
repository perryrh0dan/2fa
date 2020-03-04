import { generateSecret } from '../src/utils'

describe("Generator tests", function() {
  it("Normal generation with defaults", function() {
    var secret = generateSecret();
    expect(secret.secret.length).toBe(32);
  });
});
