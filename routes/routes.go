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
	orderRepo := repositories.NewOrderRepository(db)
	cartRepo := repositories.NewCartRepository(db)
	handler := handlers.NewHandler(userRepo, brandRepo, productRepo, cartRepo, orderRepo)

	api := e.Group("/api/v1")

	// ==================== AUTH ====================
	auth := api.Group("/auth")
	auth.POST("/signup", handler.CreateUser)
	auth.POST("/signin", handler.SignIn)
	auth.GET("/check-auth", middleware.Auth(handler.CheckAuth))
	auth.PUT("/change-password", middleware.Auth(handler.ChangePassword))

	// ==================== USERS ====================
	users := api.Group("/users")
	users.POST("", handler.CreateUser)
	users.GET("", handler.GetAllUsers)
	users.GET("/:id", handler.GetUser)
	users.PUT("/:id", handler.UpdateUser)
	users.DELETE("/:id", handler.DeleteUser)
	users.GET("/paginate", handler.GetAllUsersWithPagination)

	// Tambahan endpoint user-specific
	users.GET("/me/orders", middleware.Auth(handler.GetMyOrders))
	users.GET("/me/cart", middleware.Auth(handler.GetMyCart))

	// ==================== BRANDS ====================
	brands := api.Group("/brands")
	brands.POST("", middleware.Auth(handler.CreateBrand))
	brands.GET("", handler.GetAllBrands)
	brands.GET("/:id", handler.GetBrandByID)
	brands.PUT("/:id", middleware.Auth(handler.UpdateBrand))
	brands.DELETE("/:id", middleware.Auth(handler.DeleteBrand))

	// ==================== PRODUCTS ====================
	products := api.Group("/products")
	products.POST("", middleware.Auth(handler.CreateProduct))
	products.GET("", handler.GetAllProducts)
	products.GET("/:id", handler.GetProductByID)
	products.PUT("/:id", middleware.Auth(handler.UpdateProduct))
	products.DELETE("/:id", middleware.Auth(handler.DeleteProduct))
	products.GET("/brand/:brand_id", handler.GetProductsByBrandID)
	products.GET("/paginate", handler.GetAllProductsWithPagination)

	// ==================== CART ====================
	carts := api.Group("/carts", middleware.Auth)
	carts.POST("", handler.CreateCart)
	carts.GET("/my", handler.GetMyCart)
	carts.GET("/all", handler.GetAllCarts)
	carts.GET("/:id", handler.GetCartByID)
	carts.PUT("/:id", handler.UpdateCart)
	carts.DELETE("/:id", handler.DeleteCart)
	carts.GET("/paginate", handler.GetAllCartsWithPagination)

	// ==================== ORDERS ====================
	orders := api.Group("/orders", middleware.Auth)
	orders.POST("", handler.CreateOrder)
	orders.GET("/me", handler.GetMyOrders)
	orders.GET("/:id", handler.GetOrderByID)
	orders.PUT("/:id", handler.UpdateOrder)
	orders.DELETE("/:id", handler.DeleteOrder)
	orders.GET("/all", handler.GetAllOrders)
	orders.GET("/paginate", handler.GetAllOrderWithPagination)
}
