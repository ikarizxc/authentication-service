package main

import (
	"authentication-service/internal/config"
	"authentication-service/internal/controllers/authController"
	"authentication-service/internal/storage/mongo"
	"log"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// cfg
	cfg := config.MustLoad()

	// env
	if err := godotenv.Load(); err != nil {
		log.Fatal("no .env file found")
	}

	// storage
	storage, err := mongo.New()
	if err != nil {
		log.Fatal("failed to init db connection")
	}

	defer func() {
		if err := storage.Disconnect(); err != nil {
			log.Fatal("failed to close db connection", slog.String("error", err.Error()))
		}
	}()

	_ = storage

	// routes
	router := gin.Default()

	authController := authController.AuthController{Storage: storage}

	router.GET("/", authController.GetTokens)

	// server
	log.Println("starting server")

	srv := &http.Server{
		Addr:         cfg.HTTPServer.Address,
		Handler:      router,
		ReadTimeout:  cfg.HTTPServer.Timeout,
		WriteTimeout: cfg.HTTPServer.Timeout,
		IdleTimeout:  cfg.HTTPServer.IdleTimeout,
	}

	if err := srv.ListenAndServe(); err != nil {
		log.Fatal("failed to start server")
	}

	log.Fatal("server stopped")
}
