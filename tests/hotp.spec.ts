import { hotpGenerate } from "../src/hotp";

describe("HOTP Counter-Based Algorithm Test", function() {
  describe("normal operation with secret = '12345678901234567890' at counter 3", function() {
    it("should return correct one-time password", function() {
      var topic = hotpGenerate({ secret: "12345678901234567890", counter: 3 });
      expect(topic).toBe("969429");
    });
  });

  describe("another counter normal operation with secret = '12345678901234567890' at counter 7", function() {
    it("should return correct one-time password", function() {
      var topic = hotpGenerate({ secret: "12345678901234567890", counter: 7 });
      expect(topic).toBe("162583");
    });
  });

  describe("digits override with secret = '12345678901234567890' at counter 4 and digits = 8", function() {
    it("should return correct one-time password", function() {
      var topic = hotpGenerate({
        secret: "12345678901234567890",
        counter: 4,
        digits: 8
      });
      expect(topic).toBe("40338314");
    });
  });
});
