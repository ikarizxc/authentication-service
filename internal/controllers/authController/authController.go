package authController

import (
	tokenController "authentication-service/internal/controllers/tokenController"
	"authentication-service/internal/storage/mongo"
	"authentication-service/internal/tokens"
	"encoding/base64"
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

	// generate token pair
	accessToken, refreshToken, err := tokenController.GenerateTokenPair(guid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	// refreshtoken to base64
	refreshTokenBase64 := base64.StdEncoding.EncodeToString([]byte(refreshToken))

	// refreshtoken to bcrypt hash
	refreshTokenBcrypt, err := tokens.GenerateHashToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	// rewrite refresh token in db
	if err := authController.RewriteRefreshToken(guid, refreshTokenBcrypt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	SetCookie(c, accessToken, refreshTokenBase64)

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshTokenBase64,
	})
}

func (authController *AuthController) RefreshTokens(c *gin.Context) {
	guid := c.Query("guid")
	if guid == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "invalid guid in query",
		})
		return
	}

	cookieAccessToken, err := c.Cookie("accessToken")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		c.Error(err)
		return
	}

	cookieRefreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		c.Error(err)
		return
	}

	// check if refreshtoken is expired
	// if cookieRefreshToken.MaxAge <= time.Now() {
	// 	c.JSON(http.StatusUnauthorized, gin.H{
	// 		"message": "unauthorized",
	// 	})
	// 	c.Error(err)
	// 	return
	// }

	refreshTokenDecryptedBytes, err := base64.StdEncoding.DecodeString(cookieRefreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	refreshTokenDecrypted := string(refreshTokenDecryptedBytes)

	// match refreshtoken with accesstoken
	if refreshTokenDecrypted[len(refreshTokenDecrypted)-8:] != cookieAccessToken[len(cookieAccessToken)-8:] {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "unauthorized",
		})
		c.Error(err)
		return
	}

	// match with refreshtokenhash from db
	refreshTokenHashFromStorage, err := authController.Storage.ReadRefreshToken(guid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(refreshTokenHashFromStorage), refreshTokenDecryptedBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	// generate token pair
	accessToken, refreshToken, err := tokenController.GenerateTokenPair(guid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	// refreshtoken to base64
	refreshTokenBase64 := base64.StdEncoding.EncodeToString([]byte(refreshToken))

	// refreshtoken to bcrypt hash
	refreshTokenBcrypt, err := tokens.GenerateHashToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	// rewrite refresh token in db
	if err := authController.RewriteRefreshToken(guid, refreshTokenBcrypt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "internal server error",
		})
		c.Error(err)
		return
	}

	SetCookie(c, accessToken, refreshTokenBase64)

	c.JSON(http.StatusOK, gin.H{
		"accessToken":  accessToken,
		"refreshToken": refreshTokenBase64,
	})
}

func (authController *AuthController) RewriteRefreshToken(guid, refreshTokenBcrypt string) error {
	if rt, err := authController.Storage.ReadRefreshToken(guid); rt == "" && err == nil {
		// guid does not exist
		err = authController.Storage.WriteRefreshToken(guid, string(refreshTokenBcrypt))
		if err != nil {
			return err
		}
	} else if rt != "" && err == nil {
		// guid exist
		err = authController.Storage.UpdateRefreshToken(guid, string(refreshTokenBcrypt))
		if err != nil {
			return err
		}
	} else if err != nil {
		// error occurred
		return err
	}

	return nil
}

func SetCookie(c *gin.Context, accessToken, refreshToken string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "accessToken",
		Value:    accessToken,
		MaxAge:   60 * 15,
		Path:     "/",
		Domain:   "localhost",
		Secure:   false,
		HttpOnly: true,
	})

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		MaxAge:   60 * 60 * 24 * 30,
		Path:     "/",
		Domain:   "localhost",
		Secure:   false,
		HttpOnly: true,
	})
}
