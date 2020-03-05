import { generateSecret } from '../src/secret'
import { totpGenerate, totpVerify } from '../src/totp'

describe("Test totp end to end scenario", function() {
  it("should be valid", function() {
    const secret = generateSecret({ label: "accountName", issuer: "issuerName" })
    const code =  totpGenerate({ secret: secret.secret })
    const valid = totpVerify({ secret: secret.secret, token: code }) //true

    expect(valid).toBe(true)
  })

  it("should be invalid", function() {
    const secret = generateSecret({ label: "accountName", issuer: "issuerName" })
    const code =  totpGenerate({ secret: secret.secret })
    const valid = totpVerify({ secret: secret.secret, token: code, window: -1 }) //true

    expect(valid).toBe(false)
  })
})
