package configs

var (
	HKDFInfo        = []byte("minimal-signal")
	ServerAddress   = "localhost:8080"
	RedisAddress    = "localhost:6379"
	PublishKeysPath = "/keys"
	WebSocketPath   = "/ws"

	// Redis keys

	ClientRatchetKey       = "client:ratchet:%s:%s"
	ClientMessagesKey      = "client:messages:%s:%s"
	ClientInitHandshakeKey = "client:initHandshake:%s:%s"
	ServerMessageQueueKey  = "server:messages:%s"
	ServerUserPubKey       = "publicKey:%s"

	ForwardDHRatchetChanceTotal = 20
)
