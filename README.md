# @control/otp

This package is a simple one-time-password generator.
It supports both HOTP (according to [RFC 4226](https://datatracker.ietf.org/doc/html/rfc4226) spec) and TOTP (according to [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238) spec).

> ⚠️ It only supports 8-byte counters as of now, as per the spec.

Both HOTP and TOTP have been tested according to the RFC example values.

## HOTP
HOTP (HMAC One Time Password) is an algorithm to generate one-time-use passwords. These are generated
according to a counter, which is supposed to change on every use (hence the one-time-use).

This library does not provide any mechanism to allow the counters to increment.

### Usage
```js
const { HOTP } = require('@control/otp');

const my_hotp = new HOTP({ algorithm: 'sha1', key: 'my_super_secret_key' });

const hotp_code = my_hotp.code({ counter: 25 });
```


## TOTP
TOTP (Time-based One Time Password) follows the same pattern than HOTP. The main difference is that the HOTP counter is actually
the number of time periods elapsed since a given time (usually Unix Epoch).

> ⚠️ This library assumes that the starting point is always Unix Epoch; it is, however, possible to configure

Contrary to HOTP however, TOTP does not need to increment a counter, since the counter is uniquely dependant on time (which, to make it clear, usually advances on its own).

### Usage
```js
const { TOTP } = require('@control/otp');

const my_totp = new TOTP({ algorithm: 'sha256', key: 'my_super_secret_key' });

// With a Date object
const totp_code = my_totp.code({ date: new Date('2022-04-09T14:33:00Z') });

// With a number of seconds since epoch
const totp_code = my_totp.code({ date: 1649507635 });
```

As you can see, it is possible to pass the `number of seconds since epoch`, which essentially allows you to create a custom epoch, but it requires that you make the `now - epoch` difference yourself.
