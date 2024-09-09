package main

import (
	"context"
	"minimal-signal/configs"
	"minimal-signal/server"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

var (
	logger = logrus.New()
)

// Main function to start the server
func main() {
	s := server.NewServer(
		context.Background(),
		redis.NewClient(&redis.Options{Addr: configs.RedisAddress}),
		logger,
	)
	defer s.Close()

	r := mux.NewRouter()
	r.HandleFunc(configs.WebSocketPath, s.HandleConnections)
	r.HandleFunc(configs.PublishKeysPath, s.HandlePublishKeys).Methods(http.MethodPost)

	logger.Infof("WebSocket server running on %s", configs.ServerAddress)
	if err := http.ListenAndServe(configs.ServerAddress, r); err != nil {
		logger.Fatalf("Error starting server: %v", err)
	}

	logger.Info("Closing server...")
}
