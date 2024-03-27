package authController

import (
	"authentication-service/internal/storage/mongo"
	"authentication-service/internal/token"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type AuthController struct {
	Storage *mongo.MongoDB
}

func (authController *AuthController) GetTokens(c *gin.Context) {
	guid := c.Query("guid")

	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid guid in query",
		})
		return
	}

	refreshToken, err := token.GenerateRefreshToken()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})

		return
	}

	accessToken, err := token.GenerateAccessToken(guid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})

		return
	}

	// write guid + refreshToken in db
	refreshTokenCrypted, err := bcrypt.GenerateFromPassword([]byte(refreshToken), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})

		return
	}

	authController.Storage.WriteRefreshToken(guid, string(refreshTokenCrypted))

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func RefreshToken(c *gin.Context) {

}
