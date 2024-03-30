package tokens

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type Token struct {
	Guid         string `bson:"guid"`
	RefreshToken string `bson:"refreshToken"`
}

const (
	accessTokenTTL  = time.Minute * 15
	refreshTokenTTL = time.Hour * 12
)

func GenerateRefreshToken(accessToken string) (string, error) {
	refreshToken := GenerateRandomToken()

	refreshToken += accessToken[len(accessToken)-8:]

	return refreshToken, nil
}

func GenerateAccessToken(guid string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, GetClaims(guid, accessTokenTTL))

	accessToken, err := token.SignedString([]byte(os.Getenv("JWT_SIGN_STRING")))
	if err != nil {
		return "", fmt.Errorf("error while generating access token")
	}

	return accessToken, nil
}

func GetClaims(guid string, ttl time.Duration) *jwt.MapClaims {
	return &jwt.MapClaims{
		"sub": guid,
		"exp":  &jwt.NumericDate{Time: time.Now().Add(ttl)},
	}
}

func GenerateRandomToken() string {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	chars := []rune("abcdefghijklmnopqrstuvwxyz" +
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"0123456789")

	newString := make([]rune, 16)

	for i := range newString {
		newString[i] = chars[rnd.Intn(len(chars))]
	}

	return string(newString)
}

func GenerateHashToken(token string) (string, error) {
	hashToken, err := bcrypt.GenerateFromPassword([]byte(token), bcrypt.DefaultCost)
	return string(hashToken), err
}
