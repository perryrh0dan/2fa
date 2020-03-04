import { hotpGenerate } from "../src/hotp";

describe("normal operation with secret = '12345678901234567890' at counter 3", function() {
  it("should return correct one-time password", function() {
    var topic = hotpGenerate({ secret: "12345678901234567890", counter: 3 });
    expect(topic).toBe("969429");
  });
});
