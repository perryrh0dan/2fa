<h1 align="center">
  2FA
</h1>

<h4 align="center">
  TOTP and HOTP package for nodejs
</h4>

<div align="center">
  
</div>

## Descriptions

2fa is a node.js package for generating and verifying one-time passwords. It can be used to implement two-factor (2FA) or multi-factor(MFA) authentication methods in anywhere that requires users to log in.

Open MFA standards are defined in RFC [4226]([https://tools.ietf.org/html/rfc4226) (HOTP: An HMAC-Based One-Time Password Algorithm) and in RFC [6238](https://tools.ietf.org/html/rfc6238) (TOTP: Time-Based One-Time Password Algorithm). GOTP implements server-side support for both of these standards.

## Highlights

## Contents

- [Description](#description)
- [Highlights](#highlights)
- [Install](#install)
- [Usage](#usage)
- [Development](#development)
- [Team](#team)
- [License](#license)

## Install

``` bash
npm install @perryrh0dan/2fa
```

## Usage

### Time-based OTPs

``` ts
// Generate secret
secret = generateSecret("accountName", "issuerName")

// Generate code
code totpGenerate(secret.secret)

// VerifyCode
totpVerify(code) //true

// Generate a Provisioning URI
secret.otpauthURL()
// otpauth://totp/issuerName:accountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
```

### Counter-based OTPs
``` ts

```

## Development

## Team

- Thomas Pöhlmann [(@perryrh0dan)](https://github.com/perryrh0dan)

## License

[MIT](https://github.com/perryrh0dan/2fa/blob/master/license.md)
