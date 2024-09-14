# minimal-signal-protocol-go

## How to run

Requirements:

- `golang v1.22`

1. Run `redis` on Docker:

```bash
docker run -d -p 6379:6379 redis/redis-stack-server:latest
```

2. Run the server:

```bash
go run cmd/server/main.go
```

3. Run the client with a username (like `alice`):

```bash
go run cmd/client/main.go alice
```

If the username does not exist yet, new keys will be created for this user and stored in `secrets/.env.<username>` .

## Note when reading source code

- `Alice` is the message sender
- `Bob` is the message receiver
- `crypto/` contains the cryptographic utilities
- `protocol/` contains the Signal protocol implementation
