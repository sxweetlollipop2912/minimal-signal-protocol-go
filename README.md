# minimal-signal-protocol-go

### Note when reading source code

- `Alice` is the message sender
- `Bob` is the message receiver
- `crypto/` contains the cryptographic utilities
- `protocol/` contains the Signal protocol implementation

### TODO

- [ ] Make sure sender advance DH ratchet regularly (by generating new key pair) to ensure post-compromise security
- [ ] Write tests
