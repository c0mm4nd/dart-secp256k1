## 0.4.0

- **SECURITY (critical)**: replace private-key and nonce generation. The old
  `getPrivKeyByRand` produced low-entropy, structured keys, and `sign` reused it
  for the ECDSA nonce — allowing key recovery. Keys are now sampled uniformly
  from `Random.secure()`, and the nonce is derived deterministically per
  RFC 6979 (HMAC-SHA256).
- **SECURITY**: `sign` normalizes to low-S (BIP-62).
- **SECURITY**: `verify` and the uncompressed public-key parser reject points
  that are not on the curve.
- Fix `inverseMulti`: use exact `BigInt.modInverse` instead of a
  double-precision quotient that lost precision for 256-bit values.
- `getPointByBig` now uses a Montgomery ladder (constant-shape point operations).
- Add `crypto` dependency; allow Dart 3.

## 0.3.0
- implement null safety (from @andrebianchessi)
- require dart sdk>=2.12.0

## 0.2.2

- add == operator
- optimize codes

## 0.2.1

- Fix PrivateKey.generate()

## 0.2.0

- Rewrite the interface in OOP

## 0.1.1

- Add simple docstring
- Fix prefix of compressed public key hex

## 0.1.0

- Pass a basic test
- Initial version, created by Stagehand
