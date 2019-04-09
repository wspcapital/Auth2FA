package service

import (
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"strconv"
	"os"
	"time"
)

func SignJwt(claims jwt.MapClaims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func VerifyJwt(token string, secret string) (map[string]interface{}, error) {

	jwToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("There was an error")
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !jwToken.Valid {
		return nil, fmt.Errorf("Invalid authorization token")
	}
	return jwToken.Claims.(jwt.MapClaims), nil
}

func GetBearerToken(header string) (string, error) {
	if header == "" {
		return "", fmt.Errorf("An authorization header is required")
	}
	token := strings.Split(header, " ")
	if len(token) != 2 {
		return "", fmt.Errorf("Malformed bearer token")
	}
	return token[1], nil
}

func GetTokenExpiredOTPPeriod() (int64, error)  {
	tokenExpFactor, err := strconv.Atoi(os.Getenv("Token_Expired_OTP_Factor"))
	if err != nil {
		return 0, err
	}
	return time.Now().Add(time.Minute * time.Duration(tokenExpFactor)).Unix(), nil
}

func GetTokenExpiredPeriod() (int64, error)  {
	tokenExpFactor, err := strconv.Atoi(os.Getenv("Token_Expired_Factor"))
	if err != nil {
		return 0, err
	}
	return time.Now().Add(time.Minute * time.Duration(tokenExpFactor)).Unix(), nil
}
