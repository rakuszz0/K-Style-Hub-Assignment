package jwtToken

import (
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func GetSecretKey() string {
	key := os.Getenv("SECRET_KEY")
	if key == "" {
		panic("SECRET_KEY is empty! Please check .env")
	}
	return key
}

type MapClaims = jwt.MapClaims

func GenerateToken(userID uint, isAdmin bool) (string, error) {
	claims := jwt.MapClaims{
		"id":      userID, // Langsung gunakan uint
		"isAdmin": isAdmin,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(GetSecretKey()))
}

func VerifyToken(tokenString string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(GetSecretKey()), nil
	})
}

func DecodeToken(tokenString string) (MapClaims, error) {
	token, err := VerifyToken(tokenString)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}
