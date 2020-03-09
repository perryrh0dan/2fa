<h1 align="center">
  2FA
</h1>

<h4 align="center">
  TOTP and HOTP package for nodejs
</h4>

<div align="center">
  <a href="https://travis-ci.org/perryrh0dan/2fa">
    <img alt="Build Status" src="https://travis-ci.org/perryrh0dan/2fa.svg?branch=master" />
  </a>
  <a href="https://codecov.io/gh/perryrh0dan/2fa">
    <img alt="Code Coverage" src="https://codecov.io/gh/perryrh0dan/2fa/branch/master/graph/badge.svg" />
  </a>
  <a href="https://codeclimate.com/github/perryrh0dan/2fa/maintainability">
    <img src="https://api.codeclimate.com/v1/badges/d54f93a65002540e39ea/maintainability" />
  </a>
  <a href="https://www.npmjs.com/package/@perryrh0dan/2fa">
    <img alt="NPM Downloads" src="https://img.shields.io/npm/dt/@perryrh0dan/2fa" />
  </a>
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

```bash
npm install @perryrh0dan/2fa
```

## Usage

### Time-based OTPs

```ts
// Generate secret
secret = generateSecret({ label: "accountName", issuer: "issuerName" })

// Generate code
code = totpGenerate(secret.secret)

// Verify code
totpVerify({ secret: secret.secret, token: code) //true

// Generate a provisioning URI
secret.otpauthURL()
// otpauth://totp/issuerName:accountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName
```

### Counter-based OTPs

```ts
// Generate secret
secret = generateSecret({ label: "accountName", issuer: "issuerName" })

// Generate code at counter
code = hotpGenerate(secret.secret, counter)

// Verify code
hotpVerify({ secret: secret.secret, token: code, counter: counter}) //true

// Generate a provisioning URI
secret.otpauthURL(counter)
// otpauth://hotp/issuerName:accountName?secret=4S62BZNFXXSZLCRO&issuer=issuerName&counter=counter
```

## Development

## Team

- Thomas Pöhlmann [(@perryrh0dan)](https://github.com/perryrh0dan)

## License

[MIT](https://github.com/perryrh0dan/2fa/blob/master/license.md)
