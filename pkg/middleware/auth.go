package middleware

import (
	dto "ecommerce/dto/result"
	jwtToken "ecommerce/pkg/jwt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

func Auth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		tokenString := c.Request().Header.Get("Authorization")
		if tokenString == "" {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Authorization header missing",
			})
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)
		token, err := jwtToken.VerifyToken(tokenString)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Invalid token",
			})
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Invalid token claims",
			})
		}

		// Fix: Handle all possible ID types
		var userID uint
		switch v := claims["id"].(type) {
		case float64:
			userID = uint(v) // JWT biasanya encode number sebagai float64
		case int:
			userID = uint(v)
		case uint:
			userID = v
		default:
			return c.JSON(http.StatusBadRequest, dto.ErrorResult{
				Code:    http.StatusBadRequest,
				Message: "Invalid user ID format in token",
			})
		}

		c.Set("userID", userID) // Simpan sebagai uint
		return next(c)
	}
}
