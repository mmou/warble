# Warble

Warble is an Authenticated Encryption with Additional Data (AEAD) protocol 
using the Strobe framework. 

The implementation of the AEAD traits for the Strobe struct allows for composition with other protocols, and for the transmission of any number of in-order messages.

The implementation of the AEAD traits for the Warble structs supports
the transmission of any number of unordered messages by using session keys and
nonces to ensure key uniqueness. 

Warble assumes that key exchange has already taken place.

## Known security considerations:
- This is unaudited code built on top of unaudited code.
- (keys,version,nonce,auth_data) tuple must be unique, so it is important that nonce generation ensure uniqueness at least per key.
- This protocol assumes that key exchange has already taken place. Its security relies on the strength of these keys.
- This construction is not nonce-misuse resistant.
- Implementation of anti-replay window is not thread-safe.

## Subset of resources used:
- https://strobe.sourceforge.io/examples/aead
- https://strobe.sourceforge.io/papers/strobe-latest.pdf
- https://tools.ietf.org/html/rfc5116
- https://github.com/mimoo/disco/blob/f9cbb5a4edaa29095549a514c5a84d721474c1d5/libdisco/symmetric.go
- https://noiseprotocol.org/noise.html
- https://blog.cloudflare.com/tls-nonce-nse 
- https://tools.ietf.org/html/rfc6479
- https://git.zx2c4.com/WireGuard
- https://github.com/evq/yodel
