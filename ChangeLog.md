# ChangeLog for crypto-token

## 0.2.1

* `tokenLifetime` is exact.  A token carries its issue time and is refused
  once older than `tokenLifetime`; before, it could expire up to one
  `interval` early.
* A `tokenLifetime` shorter than `interval`, or spanning 65536 intervals or
  more, no longer makes every token operation divide by zero.
  `spawnTokenManager` throws an `IOError` for a non-positive `interval`.
* The AES-GCM nonce is 96 bits, the length GCM is designed for, rather
  than 64.
* The token header is encrypted rather than masked, so tokens no longer
  reveal how their counters relate.
* The rotation thread survives a failed rotation, and its wait no longer
  overflows a 32-bit `Int`.
* Tokens are 14 bytes longer: an 8-byte issue time and a 16-byte header
  instead of 10.  Tokens never outlive the process that made them, so no
  token from an earlier version is affected.
* The lower bound on base moves to 4.11, where `GHC.Clock` is.
