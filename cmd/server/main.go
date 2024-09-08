package main

import (
	"context"
	"github.com/gorilla/mux"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"minimal-signal/server"
	"net/http"
)

var (
	logger = logrus.New()
)

// Main function to start the server
func main() {
	s := server.NewServer(
		context.Background(),
		redis.NewClient(&redis.Options{Addr: "localhost:6379"}),
		logger,
	)
	defer s.Close()

	r := mux.NewRouter() // Using gorilla/mux for more flexible routing
	r.HandleFunc("/ws", s.HandleConnections)

	logger.Info("WebSocket server running on ws://localhost:8080/ws")
	if err := http.ListenAndServe(":8080", r); err != nil {
		logger.Fatalf("Error starting server: %v", err)
	}

	logger.Info("Closing server...")
}
