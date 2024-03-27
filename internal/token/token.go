package token

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Token struct {
	AcessToken   string
	RefreshToken string
}

const (
	tokenTTL = time.Hour * 12
)

func GenerateRefreshToken() (string, error) {
	refreshToken := make([]byte, 32)
	s := rand.NewSource(time.Now().Unix())
	r := rand.New(s)

	_, err := r.Read(refreshToken)
	if err != nil {
		return "", fmt.Errorf("error while generating refresh token")
	}

	return base64.StdEncoding.EncodeToString(refreshToken), nil
}

func GenerateAccessToken(guid string) (string, error) {
	claims := jwt.MapClaims{
		"guid": guid,
		"exp":  time.Now().Add(tokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SIGN_STRING")))
	if err != nil {
		return "", fmt.Errorf("error while generating access token")
	}

	return accessToken, nil
}
