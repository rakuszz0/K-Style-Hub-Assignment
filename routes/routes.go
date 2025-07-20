package routes

import (
	handlers "ecommerce/handlers"
	"ecommerce/pkg/middleware"
	repositories "ecommerce/repository"

	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

func InitRouter(e *echo.Echo, db *gorm.DB) {
	userRepo := repositories.NewUserRepository(db)
	brandRepo := repositories.NewBrandRepository(db)
	productRepo := repositories.NewProductRepository(db)
	handler := handlers.NewHandler(userRepo, brandRepo, productRepo)

	api := e.Group("/api/v1")

	// Group untuk Auth
	auth := api.Group("/auth")
	auth.POST("/signup", handler.CreateUser)
	auth.POST("/signin", handler.SignIn)
	auth.GET("/check-auth", middleware.Auth(handler.CheckAuth))
	auth.PUT("/change-password", middleware.Auth(handler.ChangePassword))

	// Group untuk Users
	users := api.Group("/users")
	users.POST("", handler.CreateUser)
	users.GET("", handler.GetAllUsers)
	users.GET("/:id", handler.GetUser)
	users.PUT("/:id", handler.UpdateUser)
	users.DELETE("/:id", handler.DeleteUser)
	users.GET("/paginate", handler.GetAllUsersWithPagination)

	// Group untuk Brands
	brands := api.Group("/brands")
	brands.POST("", middleware.Auth(handler.CreateBrand))
	brands.GET("", handler.GetAllBrands)
	brands.GET("/:id", handler.GetBrandByID)
	brands.PUT("/:id", middleware.Auth(handler.UpdateBrand))
	brands.DELETE("/:id", middleware.Auth(handler.DeleteBrand))

	// Group untuk Products
	products := api.Group("/products")
	products.POST("", middleware.Auth(handler.CreateProduct))
	products.GET("", handler.GetAllProducts)
	products.GET("/:id", handler.GetProductByID)
	products.PUT("/:id", middleware.Auth(handler.UpdateProduct))
	products.DELETE("/:id", middleware.Auth(handler.DeleteProduct))
	products.GET("/brand/:brand_id", handler.GetProductsByBrandID)
	products.GET("/paginate", handler.GetAllProductsWithPagination)

}
