package tokenController

import (
	"authentication-service/internal/tokens"
)

func GenerateTokenPair(guid string) (string, string, error) {
	accessToken, err := tokens.GenerateAccessToken(guid)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := tokens.GenerateRefreshToken(accessToken)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}
