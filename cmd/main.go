// @title Ecommerce API
// @version 1.0
// @description This is an ecommerce service API
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@ecommerce.com

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /api/v1
// @schemes http

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
package main

import (
	"fmt"
	"log"
	"os"

	"ecommerce/database"
	_ "ecommerce/docs"
	"ecommerce/routes"

	"ecommerce/pkg/mysql"

	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echoSwagger "github.com/swaggo/echo-swagger"
)

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Failed to load .env file")
	}
	fmt.Println("SECRET_KEY from .env:", os.Getenv("SECRET_KEY"))

	// Initialize database connection
	mysql.DatabaseInit()

	// Run database migration
	database.RunMigration()

	// Create Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.POST, echo.PUT, echo.PATCH, echo.DELETE},
		AllowHeaders: []string{"X-Requested-With", "Content-Type", "Authorization"},
	}))

	// Serve static files if needed
	// e.Static("/uploads", "uploads")

	// Swagger documentation
	e.GET("/swagger/*", echoSwagger.WrapHandler)

	// Initialize routes
	routes.InitRouter(e, mysql.DB)

	// Get port from .env or fallback to default
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Println("🚀 Server running at http://localhost:" + port)
	e.Logger.Fatal(e.Start(":" + port))
}
