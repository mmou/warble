# Warble

AEAD traits and implementation using Strobe. Includes a basic implementation on Strobe, as
well as Warble, an implementation that supports AEAD sessions over an
unreliable transport. 

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
