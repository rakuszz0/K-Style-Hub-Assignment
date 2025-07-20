package middleware

import (
	dto "ecommerce/dto/result"
	jwtToken "ecommerce/pkg/jwt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
)

func Auth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		authHeader := c.Request().Header.Get("Authorization")
		if authHeader == "" {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Authorization header is missing",
			})
		}

		tokenString := strings.Replace(authHeader, "Bearer ", "", 1)
		if tokenString == "" {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Token is missing",
			})
		}

		claims, err := jwtToken.DecodeToken(tokenString)
		if err != nil {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Invalid token",
			})
		}

		userID, ok := claims["id"].(float64)
		if !ok {
			return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
				Code:    http.StatusUnauthorized,
				Message: "Invalid token claims",
			})
		}

		isAdmin, ok := claims["isAdmin"].(bool)
		if !ok {
			isAdmin = false // fallback jika tidak ada
		}

		c.Set("userLogin", int(userID))
		c.Set("isAdmin", isAdmin)
		return next(c)
	}
}
