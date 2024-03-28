package routers

import (
	"authentication-service/internal/controllers/authController"
	"authentication-service/internal/storage/mongo"

	"github.com/gin-gonic/gin"
)

func SetupRouter(storage *mongo.MongoDB) *gin.Engine {
	router := gin.Default()

	authController := authController.AuthController{Storage: storage}

	router.GET("/auth", authController.GetTokens)
	router.GET("/refresh", authController.RefreshTokens)

	return router
}
