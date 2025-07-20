package controllers

import (
	dtoAuth "ecommerce/dto/auth"
	dtoBrands "ecommerce/dto/brands"
	dtoCart "ecommerce/dto/cart"
	dtoOrder "ecommerce/dto/order"
	dtoProduct "ecommerce/dto/product"
	dto "ecommerce/dto/result"
	"ecommerce/models"
	"ecommerce/pkg/bcrypt"
	jwtToken "ecommerce/pkg/jwt"
	repo "ecommerce/repository"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
	"gorm.io/gorm"
)

type Handler struct {
	userRepository    repo.UserRepository
	brandRepository   repo.BrandRepository
	productRepository repo.ProductRepository
	cartRepository    repo.CartRepository
	orderRepository   repo.OrderRepository
}

func NewHandler(
	userRepo repo.UserRepository,
	brandRepo repo.BrandRepository,
	productRepo repo.ProductRepository,
	cartRepo repo.CartRepository,
	orderRepo repo.OrderRepository,
) *Handler {
	return &Handler{
		userRepository:    userRepo,
		brandRepository:   brandRepo,
		productRepository: productRepo,
		cartRepository:    cartRepo,
		orderRepository:   orderRepo,
	}
}

// CheckAuth godoc
// @Summary Get current authenticated user
// @Description Get details of the currently logged-in user
// @Tags Auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} dto.SuccessResult{data=models.UserResponseJWT}
// @Failure 401 {object} dto.ErrorResult
// @Router /auth/check-auth [get]
func (h *Handler) CheckAuth(c echo.Context) error {
	userId, ok := c.Get("userLogin").(int)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}
	fmt.Println("CheckAuth userId:", userId)

	user, err := h.userRepository.GetByID(uint(userId))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to get user",
		})
	}

	userResponse := models.UserResponseJWT{
		ID:       user.ID,
		Email:    user.Email,
		Name:     user.FirstName + " " + user.LastName,
		Phone:    user.Phone,
		Address:  user.Address,
		Username: user.Username,
		IsAdmin:  user.IsAdmin,
		Token:    "",
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: userResponse,
	})
}

// ChangePassword godoc
// @Summary Change user's password
// @Description Change the password of the currently logged-in user
// @Tags Auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dtoAuth.ChangePasswordRequest true "Old and New Password"
// @Success 200 {object} dto.SuccessResult{data=string}
// @Failure 400,401,500 {object} dto.ErrorResult
// @Router /auth/change-password [put]
func (h *Handler) ChangePassword(c echo.Context) error {
	userLogin := c.Get("userLogin")
	if userLogin == nil {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}
	userID := userLogin.(int)

	var body struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request",
		})
	}

	user, err := h.userRepository.GetByID(uint(userID))
	if err != nil || user == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "User not found",
		})
	}

	if !bcrypt.CheckPasswordHash(body.OldPassword, user.Password) {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Old password incorrect",
		})
	}

	hashedPassword, err := bcrypt.HashingPassword(body.NewPassword)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Error hashing password",
		})
	}

	user.Password = hashedPassword
	user.UpdatedAt = time.Now()

	if err := h.userRepository.Update(user); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update password",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: "Password changed successfully",
	})
}

// SignUp godoc
// @Summary Register new user
// @Description Sign up with username, email, and password
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dtoAuth.SignUpRequest true "Sign Up Request"
// @Success 201 {object} dtoAuth.BaseResponse
// @Failure 400 {object} dto.ErrorResult
// @Failure 409 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /auth/signup [post]
func (h *Handler) CreateUser(c echo.Context) error {
	// Bind and validate request
	var req dtoAuth.SignUpRequest
	if err := c.Bind(&req); err != nil {
		log.Printf("CreateUser Bind error: %v\nRequest Body: %+v", err, req)
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body",
		})
	}

	// Log the incoming request for debugging
	log.Printf("Incoming SignUp Request: %+v", req)

	// Validate password strength
	if err := validatePassword(req.Password); err != nil {
		log.Println("Password validation failed:", err)
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: err.Error(),
		})
	}

	// Check if email already exists
	if existingUser, _ := h.userRepository.GetByEmail(req.Email); existingUser != nil {
		log.Printf("Email already exists: %s", req.Email)
		return c.JSON(http.StatusConflict, dto.ErrorResult{
			Code:    http.StatusConflict,
			Message: "Email already registered",
		})
	}

	// Check if username already exists
	if existingUser, _ := h.userRepository.GetByUsername(req.Username); existingUser != nil {
		log.Printf("Username already exists: %s", req.Username)
		return c.JSON(http.StatusConflict, dto.ErrorResult{
			Code:    http.StatusConflict,
			Message: "Username already taken",
		})
	}

	// Hash password
	hashedPassword, err := bcrypt.HashingPassword(req.Password)
	if err != nil {
		log.Printf("Password hashing error: %v", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to process password",
		})
	}

	users, err := h.userRepository.GetAll()
	if err != nil {
		log.Printf("Failed to check existing users: %v", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to check user status",
		})
	}

	isFirstUser := len(users) == 0

	// Create user model
	user := models.User{
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Username:  req.Username,
		Email:     req.Email,
		Phone:     req.Phone,
		Address:   req.Address,
		Password:  hashedPassword,
		IsAdmin:   isFirstUser, // Default to admin if first user
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	log.Printf("Attempting to create user: %+v", user)

	// Create user in database
	if err := h.userRepository.Create(&user); err != nil {
		log.Printf("User creation failed: %v\nDetailed error: %+v", err, err)

		// Handle specific database errors
		var errorMsg string
		if strings.Contains(err.Error(), "duplicate key") {
			if strings.Contains(err.Error(), "email") {
				errorMsg = "Email already registered"
			} else if strings.Contains(err.Error(), "username") {
				errorMsg = "Username already taken"
			} else if strings.Contains(err.Error(), "phone") {
				errorMsg = "Phone number already registered"
			} else {
				errorMsg = "User with similar details already exists"
			}
			return c.JSON(http.StatusConflict, dto.ErrorResult{
				Code:    http.StatusConflict,
				Message: errorMsg,
			})
		}

		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create user account",
		})
	}

	log.Printf("User created successfully: %d - %s", user.ID, user.Email)

	// Generate JWT token
	claims := jwt.MapClaims{
		"id":      user.ID,
		"email":   user.Email,
		"isAdmin": user.IsAdmin,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	token, err := tokenObj.SignedString([]byte(jwtToken.GetSecretKey()))
	if err != nil {
		log.Printf("Token generation failed: %v", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate authentication token",
		})
	}

	// Prepare response
	authData := dtoAuth.AuthData{
		ID:        uint(user.ID),
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Username:  user.Username,
		Phone:     user.Phone,
		Address:   user.Address,
		Email:     user.Email,
		IsAdmin:   user.IsAdmin,
		Token:     token,
	}

	return c.JSON(http.StatusCreated, dtoAuth.NewAuthResponse("Registration successful!", authData))
}

// Helper function to validate password strength
func validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var (
		hasUpper   = false
		hasLower   = false
		hasNumber  = false
		hasSpecial = false
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case strings.ContainsRune("!@#$%^&*", char):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return fmt.Errorf("password must contain at least one number")
	}
	if !hasSpecial {
		return fmt.Errorf("password must contain at least one special character (!@#$%%^&*)")
	}

	return nil
}

// SignIn godoc
// @Summary Login user
// @Tags Auth
// @Accept json
// @Produce json
// @Param request body dtoAuth.SignInRequest true "Login credentials"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,401 {object} dto.ErrorResult
// @Router /auth/signin [post]
func (h *Handler) SignIn(c echo.Context) error {
	var req dtoAuth.SignInRequest
	if err := c.Bind(&req); err != nil {
		log.Println("SignIn Bind error:", err)
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body",
		})
	}

	req.Value = strings.TrimSpace(req.Value)
	req.Password = strings.TrimSpace(req.Password)

	var user *models.User
	var err error

	if strings.Contains(req.Value, "@") {
		user, err = h.userRepository.GetByEmail(req.Value)
		log.Printf("Looking up by email: %s", req.Value)
	} else {
		user, err = h.userRepository.GetByUsername(req.Value)
		log.Printf("Looking up by username: %s", req.Value)
	}

	if err != nil || user == nil {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Invalid username/email or password",
		})
	}

	if !bcrypt.CheckPasswordHash(req.Password, user.Password) {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Invalid username/email or password",
		})
	}

	claims := jwt.MapClaims{
		"id":       user.ID,
		"email":    user.Email,
		"username": user.Username,
		"isAdmin":  user.IsAdmin,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	}
	tokenObj := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	secretKey := []byte(jwtToken.GetSecretKey())

	token, err := tokenObj.SignedString(secretKey)
	if err != nil {
		log.Println("SignIn GenerateToken error:", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to generate authentication token",
		})
	}

	// Prepare response
	response := dto.SuccessResult{
		Code: http.StatusOK,
		Data: map[string]interface{}{
			"token": token,
			"user": models.UserResponseJWT{
				ID:       user.ID,
				Name:     user.FirstName + " " + user.LastName,
				Email:    user.Email,
				Username: user.Username,
				Phone:    user.Phone,
				Address:  user.Address,
				IsAdmin:  user.IsAdmin,
			},
		},
	}

	return c.JSON(http.StatusOK, response)
}

// GetUser godoc
// @Summary Get user by ID
// @Tags User
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404 {object} dto.ErrorResult
// @Router /users/{id} [get]
func (h *Handler) GetUser(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid user ID format",
		})
	}

	user, err := h.userRepository.GetByID(uint(id))
	if err != nil || user == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "User not found",
		})
	}

	response := models.UserResponseJWT{
		ID:       user.ID,
		Name:     user.FirstName + " " + user.LastName,
		Email:    user.Email,
		Username: user.Username,
		Phone:    user.Phone,
		Address:  user.Address,
		IsAdmin:  user.IsAdmin,
		Token:    "",
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// GetAllUsers godoc
// @Summary Get all users
// @Tags User
// @Produce json
// @Success 200 {object} dto.SuccessResult
// @Failure 500 {object} dto.ErrorResult
// @Router /users [get]
func (h *Handler) GetAllUsers(c echo.Context) error {
	users, err := h.userRepository.GetAll()
	if err != nil {
		log.Println("GetAllUsers error:", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to get users",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: users,
	})
}

// UpdateUser godoc
// @Summary Update user by ID
// @Tags User
// @Accept json
// @Produce json
// @Param id path int true "User ID"
// @Param request body models.User true "User Update Data"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /users/{id} [put]
func (h *Handler) UpdateUser(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid user ID format",
		})
	}

	user, err := h.userRepository.GetByID(uint(id))
	if err != nil {
		log.Println("UpdateUser GetByID error:", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to get user",
		})
	}

	if user == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "User not found",
		})
	}

	if err := c.Bind(user); err != nil {
		log.Println("UpdateUser Bind error:", err)
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body",
		})
	}

	user.UpdatedAt = time.Now()

	if err := h.userRepository.Update(user); err != nil {
		log.Println("UpdateUser Update error:", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update user",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: user,
	})
}

// DeleteUser godoc
// @Summary Delete user by ID
// @Tags User
// @Produce json
// @Param id path int true "User ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /users/{id} [delete]
func (h *Handler) DeleteUser(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid user ID format",
		})
	}

	if err := h.userRepository.Delete(uint(id)); err != nil {
		log.Println("DeleteUser Delete error:", err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to delete user",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: "User deleted successfully",
	})
}

// GetAllUsersWithPagination godoc
// @Summary Get all users with pagination
// @Description Get paginated list of users
// @Tags users
// @Accept  json
// @Produce  json
// @Param page query int true "Page number"
// @Param limit query int true "Limit per page"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /users/paginate [get]
func (h *Handler) GetAllUsersWithPagination(c echo.Context) error {
	pageStr := c.QueryParam("page")
	limitStr := c.QueryParam("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}

	users, total, err := h.userRepository.GetAllWithPagination(page, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch users",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: map[string]interface{}{
			"users": users,
			"total": total,
			"page":  page,
			"limit": limit,
		},
	})
}

// CreateBrand godoc
// @Summary Create a new brand
// @Description Create a new brand (admin only)
// @Tags Brand
// @Accept  json
// @Produce  json
// @Param brand body ecommerce_dto_brands.BrandRequest true "Brand data"
// @Success 200 {object} dto.SuccessResult{data=ecommerce_dto_brands.BrandResponse}
// @Failure 400,401,500 {object} dto.ErrorResult
// @Router /brands [post]
// @Security BearerAuth
func (h *Handler) CreateBrand(c echo.Context) error {
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized, admin access required",
		})
	}

	var req dtoBrands.BrandRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid input",
		})
	}

	// Mapping dari DTO ke Model
	brand := models.Brand{
		Name: req.Name,
	}

	if err := h.brandRepository.Create(&brand); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create brand",
		})
	}

	// Mapping ke DTO Response
	resp := dtoBrands.BrandResponse{
		ID:   brand.ID,
		Name: brand.Name,
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: resp,
	})
}

// GetAllBrands godoc
// @Summary Get all brands
// @Description Get a list of all brands
// @Tags Brand
// @Produce json
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /brands [get]
func (h *Handler) GetAllBrands(c echo.Context) error {
	brands, err := h.brandRepository.GetAll()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch brands",
		})
	}

	// Mapping model -> DTO
	var brandResponses []dtoBrands.BrandResponse
	for _, b := range brands {
		var products []dtoBrands.BrandProductResponse
		for _, p := range b.Products {
			products = append(products, dtoBrands.BrandProductResponse{
				ID:       p.ID,
				Name:     p.Name,
				Price:    p.Price,
				Quantity: p.Quantity,
			})
		}

		brandResponses = append(brandResponses, dtoBrands.BrandResponse{
			ID:       b.ID,
			Name:     b.Name,
			Products: products,
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: brandResponses,
	})
}

// GetBrandByID godoc
// @Summary Get brand by ID
// @Description Get a brand by its ID
// @Tags Brand
// @Produce json
// @Param id path int true "Brand ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /brands/{id} [get]
func (h *Handler) GetBrandByID(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid brand ID",
		})
	}

	brand, err := h.brandRepository.GetByID(uint(id))
	if err != nil || brand.ID == 0 {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Brand not found",
		})
	}

	// Mapping model -> DTO
	var products []dtoBrands.BrandProductResponse
	for _, p := range brand.Products {
		products = append(products, dtoBrands.BrandProductResponse{
			ID:       p.ID,
			Name:     p.Name,
			Price:    p.Price,
			Quantity: p.Quantity,
		})
	}

	brandResponse := dtoBrands.BrandResponse{
		ID:       brand.ID,
		Name:     brand.Name,
		Products: products,
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: brandResponse,
	})
}

// UpdateBrand godoc
// @Summary Update a brand by ID
// @Description Update a brand's details (Admin only)
// @Tags Brand
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param id path int true "Brand ID"
// @Param brand body dtoBrands.BrandRequest true "Brand data"
// @Success 200 {object} dto.SuccessResult{data=dtoBrands.BrandResponse}
// @Failure 400 {object} dto.ErrorResult
// @Failure 401 {object} dto.ErrorResult
// @Failure 404 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /brands/{id} [put]
func (h *Handler) UpdateBrand(c echo.Context) error {
	// Admin check
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized, admin access required",
		})
	}

	// Validate ID
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid brand ID format",
		})
	}

	// Bind and validate request
	var req dtoBrands.BrandRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body",
		})
	}

	// Check if brand exists
	existingBrand, err := h.brandRepository.GetByID(uint(id))
	if err != nil || existingBrand.ID == 0 {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Brand not found",
		})
	}

	// Update brand
	updatedBrand := models.Brand{
		ID:   uint(id),
		Name: req.Name,
	}

	if err := h.brandRepository.Update(&updatedBrand); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update brand",
		})
	}

	// Prepare response
	response := dtoBrands.BrandResponse{
		ID:   updatedBrand.ID,
		Name: updatedBrand.Name,
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// DeleteBrand godoc
// @Summary Delete a brand by ID
// @Description Delete a brand from the system
// @Tags Brand
// @Produce json
// @Param id path int true "Brand ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /brands/{id} [delete]
func (h *Handler) DeleteBrand(c echo.Context) error {
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized, admin access required",
		})
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid brand ID format",
		})
	}

	if err := h.brandRepository.Delete(uint(id)); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to delete brand",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: "Brand deleted successfully",
	})
}

// CreateProduct godoc
// @Summary Create a new product
// @Description Create a new product with brand association (admin only)
// @Tags Product
// @Accept json
// @Produce json
// @Param brand body ecommerce_dto_product.ProductRequest true "Product data"
// @Success 200 {object} dto.SuccessResult{data=ecommerce_dto_product.ProductResponse}
// @Failure 400,401,500 {object} dto.ErrorResult
// @Router /products [post]
// @Security BearerAuth
func (h *Handler) CreateProduct(c echo.Context) error {

	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized: Admin access required",
		})
	}

	var req dtoProduct.ProductRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid input data",
		})
	}

	brand, err := h.brandRepository.GetByID(req.BrandID)
	if err != nil || brand.ID == 0 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Brand not found",
		})
	}

	product := models.Product{
		Name:     req.Name,
		Price:    req.Price,
		Quantity: req.Quantity,
		BrandID:  req.BrandID,
	}

	if err := h.productRepository.Create(&product); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create product",
		})
	}

	response := dtoProduct.ProductResponse{
		ID:       product.ID,
		Name:     product.Name,
		Price:    product.Price,
		Quantity: product.Quantity,
		BrandID:  product.BrandID,
	}

	return c.JSON(http.StatusCreated, dto.SuccessResult{
		Code: http.StatusCreated,
		Data: response,
	})
}

// GetAllProducts godoc
// @Summary Get all products
// @Description Get a list of all products
// @Tags Product
// @Produce json
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /products [get]
func (h *Handler) GetAllProducts(c echo.Context) error {
	products, err := h.productRepository.GetAll()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch products",
		})
	}
	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: products,
	})
}

// GetProductByID godoc
// @Summary Get product by ID
// @Description Get a product by its ID
// @Tags Product
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /products/{id} [get]
func (h *Handler) GetProductByID(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid product ID format",
		})
	}

	product, err := h.productRepository.GetByID(uint(id))
	if err != nil || product == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Product not found",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: product,
	})
}

// UpdateProduct godoc
// @Summary Update a product by ID
// @Description Update a product by its ID
// @Tags Product
// @Accept json
// @Produce json
// @Param id path int true "Product ID"
// @Param product body models.Product true "Product data"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /products/{id} [put]
func (h *Handler) UpdateProduct(c echo.Context) error {
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized, admin access required",
		})
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid product ID format",
		})
	}

	var product models.Product
	if err := c.Bind(&product); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid input",
		})
	}
	product.ID = uint(id)

	if err := h.productRepository.Update(&product); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update product",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: product,
	})
}

// DeleteProduct godoc
// @Summary Delete a product by ID
// @Description Delete a product from the system
// @Tags Product
// @Produce json
// @Param id path int true "Product ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /products/{id} [delete]
func (h *Handler) DeleteProduct(c echo.Context) error {
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized, admin access required",
		})
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid product ID format",
		})
	}

	if err := h.productRepository.Delete(uint(id)); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to delete product",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: "Product deleted successfully",
	})
}

// GetProductsByBrandID godoc
// @Summary Get products by brand ID
// @Description Get all products associated with a specific brand ID
// @Tags Product
// @Produce json
// @Param brand_id path int true "Brand ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /products/brand/{brand_id} [get]
func (h *Handler) GetProductsByBrandID(c echo.Context) error {
	brandID, err := strconv.Atoi(c.Param("brand_id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid brand ID format",
		})
	}

	products, err := h.productRepository.GetByBrandID(uint(brandID))
	if err != nil || len(products) == 0 {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "No products found for this brand",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: products,
	})
}

// GetAllProductsWithPagination godoc
// @Summary Get all products with pagination
// @Description Get paginated list of products
// @Tags Product
// @Accept json
// @Produce json
// @Param page query int true "Page number"
// @Param limit query int true "Limit per page"
// @Success 200 {object} dto.SuccessResult
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /products/paginate [get]
func (h *Handler) GetAllProductsWithPagination(c echo.Context) error {
	pageStr := c.QueryParam("page")
	limitStr := c.QueryParam("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	}

	products, total, err := h.productRepository.GetAllWithPagination(page, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch products",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: map[string]interface{}{
			"products": products,
			"total":    total,
			"page":     page,
			"limit":    limit,
		},
	})
}

// CreateOrder godoc
// @Summary Create a new order
// @Description Create a new order for a user
// @Tags Order
// @Accept json
// @Produce json
// @Param request body dtoOrder.OrderRequest true "Order data"
// @Success 201 {object} dto.SuccessResult{data=dtoOrder.OrderResponse}
// @Failure 400,401,404,500 {object} dto.ErrorResult
// @Router /orders [post]
// @Security BearerAuth
func (h *Handler) CreateOrder(c echo.Context) error {

	userIDInterface := c.Get("userLogin")
	userID, ok := userIDInterface.(float64)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}

	var req dtoOrder.OrderRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid input data",
		})
	}

	// Ambil data produk dari DB untuk validasi & response
	product, err := h.productRepository.GetByID(req.ProductID)
	if err != nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Product not found",
		})
	}

	order := models.Order{
		UserID:    uint(userID),
		ProductID: req.ProductID,
		Quantity:  req.Quantity,
		Status:    "pending",
	}

	if err := h.orderRepository.Create(&order); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to create order",
		})
	}

	response := dtoOrder.OrderResponse{
		ID:        order.ID,
		UserID:    order.UserID,
		ProductID: order.ProductID,
		Quantity:  order.Quantity,
		Status:    order.Status,
		Product: dtoOrder.Product{
			ID:       product.ID,
			Name:     product.Name,
			Price:    product.Price,
			Quantity: product.Quantity,
			BrandID:  product.BrandID,
		},
	}

	return c.JSON(http.StatusCreated, dto.SuccessResult{
		Code: http.StatusCreated,
		Data: response,
	})
}

// GetOrdersByUser godoc
// @Summary Get orders by user ID
// @Description Get all orders placed by a specific user
// @Tags Order
// @Produce json
// @Success 200 {object} dto.SuccessResult{data=[]dtoOrder.OrderResponse}
// @Failure 400,401,404,500 {object} dto.ErrorResult
// @Router /orders/user [get]
// @Security BearerAuth
func (h *Handler) GetOrdersByUser(c echo.Context) error {
	userIDInterface := c.Get("userLogin")
	userIDFloat, ok := userIDInterface.(float64)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}
	userID := uint(userIDFloat)

	orders, err := h.orderRepository.GetByUserID(userID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch orders",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: orders,
	})
}

// GetOrderByID godoc
// @Summary Get order by ID
// @Description Get details of a specific order by its ID
// @Tags Order
// @Produce json
// @Param id path int true "Order ID"
// @Success 200 {object} dto.SuccessResult{data=dtoOrder.OrderResponse}
// @Failure 400,404,500 {object} dto.ErrorResult
// @Router /orders/{id} [get]
// @Security BearerAuth
func (h *Handler) GetOrderByID(c echo.Context) error {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil || orderID <= 0 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid order ID format",
		})
	}

	order, err := h.orderRepository.GetByID(uint(orderID))
	if err != nil {
		// Bisa karena error DB, atau record tidak ditemukan
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch order",
		})
	}

	if order == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Order not found",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: order,
	})
}

// GetAllOrders godoc
// @Summary Get all orders
// @Description Get a list of all orders (admin only)
// @Tags Order
// @Produce json
// @Success 200 {object} dto.SuccessResult{data=[]dtoOrder.OrderResponse}
// @Failure 400,401,404,500 {object} dto.ErrorResult
// @Router /orders [get]
// @Security BearerAuth
func (h *Handler) GetAllOrders(c echo.Context) error {
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized: admin access only",
		})
	}

	orders, err := h.orderRepository.GetAll()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch orders",
		})
	}

	if len(orders) == 0 {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "No orders found",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: orders,
	})
}

// UpdateOrder godoc
// @Summary Update an order by ID
// @Description Update the status of an order (admin only), or quantity (user)
// @Tags Order
// @Accept json
// @Produce json
// @Param id path int true "Order ID"
// @Param request body dtoOrder.OrderRequest true "Order update data"
// @Success 200 {object} dto.SuccessResult{data=dtoOrder.OrderResponse}
// @Failure 400,401,403,404,500 {object} dto.ErrorResult
// @Router /orders/{id} [put]
// @Security BearerAuth
func (h *Handler) UpdateOrder(c echo.Context) error {
	// Ambil informasi role & user ID
	isAdmin, _ := c.Get("isAdmin").(bool)
	userIDFloat, ok := c.Get("userLogin").(float64)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}
	userID := uint(userIDFloat)

	// Validasi ID order dari param
	orderID, err := strconv.Atoi(c.Param("id"))
	if err != nil || orderID <= 0 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid order ID format",
		})
	}

	// Ambil data order dari repo
	order, err := h.orderRepository.GetByID(uint(orderID))
	if err != nil || order == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Order not found",
		})
	}

	// Jika user bukan admin, pastikan hanya bisa edit order miliknya
	if !isAdmin && order.UserID != userID {
		return c.JSON(http.StatusForbidden, dto.ErrorResult{
			Code:    http.StatusForbidden,
			Message: "Forbidden: you can only update your own order",
		})
	}

	// Bind request
	var req dtoOrder.OrderUpdateRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid input data",
		})
	}

	// Role-based update
	if isAdmin {
		// Admin bisa update semua field
		if req.Quantity > 0 {
			order.Quantity = req.Quantity
		}
		if req.Status != "" {
			order.Status = req.Status
		}
	} else {
		// User biasa hanya boleh update quantity
		if req.Quantity <= 0 {
			return c.JSON(http.StatusBadRequest, dto.ErrorResult{
				Code:    http.StatusBadRequest,
				Message: "Quantity must be greater than 0",
			})
		}
		order.Quantity = req.Quantity
	}

	if err := h.orderRepository.Update(order); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update order",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: order,
	})
}

// DeleteOrder godoc
// @Summary Delete an order
// @Description Delete an order by ID
// @Tags Orders
// @Produce json
// @Param id path int true "Order ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400 {object} dto.ErrorResult
// @Failure 404 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /orders/{id} [delete]
func (h *Handler) DeleteOrder(c echo.Context) error {
	// Get and validate ID
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid order ID format",
		})
	}

	// Check if order exists first
	if _, err := h.orderRepository.GetByID(uint(id)); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, dto.ErrorResult{
				Code:    http.StatusNotFound,
				Message: "Order not found",
			})
		}
		log.Printf("Error checking order existence (ID: %d): %v", id, err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to verify order",
		})
	}

	// Delete order
	if err := h.orderRepository.Delete(uint(id)); err != nil {
		log.Printf("Failed to delete order (ID: %d): %v", id, err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to delete order",
		})
	}

	log.Printf("Successfully deleted order ID: %d", id)
	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: "Order deleted successfully",
	})
}

// GetAllOrderWithPagination godoc
// @Summary Get paginated list of orders
// @Description Retrieve orders with pagination support
// @Tags Orders
// @Accept json
// @Produce json
// @Param page query int false "Page number (default: 1)" minimum(1)
// @Param limit query int false "Number of items per page (default: 10)" minimum(1) maximum(100)
// @Success 200 {object} dto.SuccessResult{data=OrderPaginationResponse}
// @Failure 400 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /orders [get]
func (h *Handler) GetAllOrderWithPagination(c echo.Context) error {
	// Parse and validate pagination parameters
	pageStr := c.QueryParam("page")
	limitStr := c.QueryParam("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	} else if limit > 100 {
		limit = 100 // Enforce maximum limit to prevent excessive load
	}

	// Get paginated orders
	orders, total, err := h.orderRepository.GetAllWithPagination(page, limit)
	if err != nil {
		log.Printf("Failed to fetch orders (page: %d, limit: %d): %v", page, limit, err)
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch orders",
		})
	}

	// Calculate pagination metadata
	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	hasNext := page < totalPages
	hasPrev := page > 1

	// Prepare response
	response := OrderPaginationResponse{
		Orders:     orders,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
		HasNext:    hasNext,
		HasPrev:    hasPrev,
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// OrderPaginationResponse defines the structure for paginated order response
type OrderPaginationResponse struct {
	Orders     []models.Order `json:"orders"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	Limit      int            `json:"limit"`
	TotalPages int            `json:"total_pages"`
	HasNext    bool           `json:"has_next"`
	HasPrev    bool           `json:"has_prev"`
}

// CreateCart godoc
// @Summary Add item to cart
// @Description Add a product to the user's shopping cart
// @Tags Cart
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dtoCart.CartRequest true "Cart item details"
// @Success 201 {object} dto.SuccessResult{data=dtoCart.CartResponse}
// @Failure 400 {object} dto.ErrorResult
// @Failure 401 {object} dto.ErrorResult
// @Failure 404 {object} dto.ErrorResult
// @Failure 409 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /carts [post]
func (h *Handler) CreateCart(c echo.Context) error {
	// Get authenticated user ID
	userID, ok := c.Get("userLogin").(int)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized: User not authenticated",
		})
	}

	// Bind and validate request
	var req dtoCart.CartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body",
		})
	}

	// Validate quantity
	if req.Quantity <= 0 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Quantity must be greater than 0",
		})
	}

	// Check if product exists
	product, err := h.productRepository.GetByID(req.ProductID)
	if err != nil || product == nil {
		return c.JSON(http.StatusNotFound, dto.ErrorResult{
			Code:    http.StatusNotFound,
			Message: "Product not found",
		})
	}

	// Check product stock availability
	if product.Quantity < req.Quantity {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Insufficient product stock",
		})
	}

	// Check if item already exists in cart
	existingCart, err := h.cartRepository.GetByUserIDAndProductID(uint(userID), req.ProductID)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to check existing cart items",
		})
	}

	var cartItem *models.Cart
	if existingCart != nil {
		// Update quantity if item already exists
		existingCart.Quantity += req.Quantity
		if err := h.cartRepository.Update(existingCart); err != nil {
			return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
				Code:    http.StatusInternalServerError,
				Message: "Failed to update cart item quantity",
			})
		}
		cartItem = existingCart
	} else {
		// Create new cart item
		cartItem = &models.Cart{
			UserID:    uint(userID),
			ProductID: req.ProductID,
			Quantity:  req.Quantity,
		}
		if err := h.cartRepository.Create(cartItem); err != nil {
			return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
				Code:    http.StatusInternalServerError,
				Message: "Failed to add item to cart",
			})
		}
	}

	// Get the full cart item with product details
	fullCartItem, err := h.cartRepository.GetByID(cartItem.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to retrieve cart item details",
		})
	}

	// Prepare response
	response := dtoCart.CartResponse{
		ID:        fullCartItem.ID,
		UserID:    fullCartItem.UserID,
		ProductID: fullCartItem.ProductID,
		Quantity:  fullCartItem.Quantity,
		Product: dtoCart.Product{
			ID:       fullCartItem.Product.ID,
			Name:     fullCartItem.Product.Name,
			Price:    fullCartItem.Product.Price,
			Quantity: fullCartItem.Product.Quantity,
			BrandID:  fullCartItem.Product.BrandID,
		},
	}

	return c.JSON(http.StatusCreated, dto.SuccessResult{
		Code: http.StatusCreated,
		Data: response,
	})
}

// GetAllCarts godoc
// @Summary Get all carts
// @Description Get a list of all cart items (Admin only)
// @Tags Cart
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SuccessResult{data=[]dtoCart.CartResponse}
// @Failure 401 {object} dto.ErrorResult
// @Failure 403 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /carts [get]
func (h *Handler) GetAllCarts(c echo.Context) error {
	// Admin check
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusForbidden, dto.ErrorResult{
			Code:    http.StatusForbidden,
			Message: "Forbidden: Admin access required",
		})
	}

	carts, err := h.cartRepository.GetAll()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch carts",
		})
	}

	// Map to response format
	var response []dtoCart.CartResponse
	for _, cartItem := range carts {
		response = append(response, dtoCart.CartResponse{
			ID:        cartItem.ID,
			UserID:    cartItem.UserID,
			ProductID: cartItem.ProductID,
			Quantity:  cartItem.Quantity,
			Product: dtoCart.Product{
				ID:       cartItem.Product.ID,
				Name:     cartItem.Product.Name,
				Price:    cartItem.Product.Price,
				Quantity: cartItem.Product.Quantity,
				BrandID:  cartItem.Product.BrandID,
			},
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// GetCartByID godoc
// @Summary Get cart item by ID
// @Description Get a specific cart item by its ID
// @Tags Cart
// @Produce json
// @Security BearerAuth
// @Param id path int true "Cart Item ID"
// @Success 200 {object} dto.SuccessResult{data=dtoCart.CartResponse}
// @Failure 400 {object} dto.ErrorResult
// @Failure 401 {object} dto.ErrorResult
// @Failure 403 {object} dto.ErrorResult
// @Failure 404 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /carts/{id} [get]
func (h *Handler) GetCartByID(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid cart ID format",
		})
	}

	// Get authenticated user
	userID, ok := c.Get("userLogin").(int)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}

	cartItem, err := h.cartRepository.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, dto.ErrorResult{
				Code:    http.StatusNotFound,
				Message: "Cart item not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch cart item",
		})
	}

	// Check ownership (unless admin)
	isAdmin, _ := c.Get("isAdmin").(bool)
	if !isAdmin && cartItem.UserID != uint(userID) {
		return c.JSON(http.StatusForbidden, dto.ErrorResult{
			Code:    http.StatusForbidden,
			Message: "Forbidden: You don't have access to this cart item",
		})
	}

	response := dtoCart.CartResponse{
		ID:        cartItem.ID,
		UserID:    cartItem.UserID,
		ProductID: cartItem.ProductID,
		Quantity:  cartItem.Quantity,
		Product: dtoCart.Product{
			ID:       cartItem.Product.ID,
			Name:     cartItem.Product.Name,
			Price:    cartItem.Product.Price,
			Quantity: cartItem.Product.Quantity,
			BrandID:  cartItem.Product.BrandID,
		},
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// UpdateCart godoc
// @Summary Update cart item
// @Description Update quantity of a cart item
// @Tags Cart
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path int true "Cart Item ID"
// @Param request body dtoCart.CartRequest true "Update data"
// @Success 200 {object} dto.SuccessResult{data=dtoCart.CartResponse}
// @Failure 400 {object} dto.ErrorResult
// @Failure 401 {object} dto.ErrorResult
// @Failure 403 {object} dto.ErrorResult
// @Failure 404 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /carts/{id} [put]
func (h *Handler) UpdateCart(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid cart ID format",
		})
	}

	// Get authenticated user
	userID, ok := c.Get("userLogin").(int)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}

	// Bind request
	var req dtoCart.CartRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid request body",
		})
	}

	// Validate quantity
	if req.Quantity <= 0 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Quantity must be greater than 0",
		})
	}

	// Get existing cart item
	cartItem, err := h.cartRepository.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, dto.ErrorResult{
				Code:    http.StatusNotFound,
				Message: "Cart item not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch cart item",
		})
	}

	// Check ownership (unless admin)
	isAdmin, _ := c.Get("isAdmin").(bool)
	if !isAdmin && cartItem.UserID != uint(userID) {
		return c.JSON(http.StatusForbidden, dto.ErrorResult{
			Code:    http.StatusForbidden,
			Message: "Forbidden: You don't have access to this cart item",
		})
	}

	// Check product stock if changing product
	if req.ProductID != 0 && req.ProductID != cartItem.ProductID {
		product, err := h.productRepository.GetByID(req.ProductID)
		if err != nil || product == nil {
			return c.JSON(http.StatusBadRequest, dto.ErrorResult{
				Code:    http.StatusBadRequest,
				Message: "New product not found",
			})
		}
		if product.Quantity < req.Quantity {
			return c.JSON(http.StatusBadRequest, dto.ErrorResult{
				Code:    http.StatusBadRequest,
				Message: "Insufficient product stock",
			})
		}
		cartItem.ProductID = req.ProductID
	}

	// Update quantity
	cartItem.Quantity = req.Quantity
	if err := h.cartRepository.Update(cartItem); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to update cart item",
		})
	}

	// Get updated cart item with product details
	updatedCart, err := h.cartRepository.GetByID(uint(id))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch updated cart item",
		})
	}

	response := dtoCart.CartResponse{
		ID:        updatedCart.ID,
		UserID:    updatedCart.UserID,
		ProductID: updatedCart.ProductID,
		Quantity:  updatedCart.Quantity,
		Product: dtoCart.Product{
			ID:       updatedCart.Product.ID,
			Name:     updatedCart.Product.Name,
			Price:    updatedCart.Product.Price,
			Quantity: updatedCart.Product.Quantity,
			BrandID:  updatedCart.Product.BrandID,
		},
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// DeleteCart godoc
// @Summary Delete cart item
// @Description Remove an item from cart
// @Tags Cart
// @Produce json
// @Security BearerAuth
// @Param id path int true "Cart Item ID"
// @Success 200 {object} dto.SuccessResult
// @Failure 400 {object} dto.ErrorResult
// @Failure 401 {object} dto.ErrorResult
// @Failure 403 {object} dto.ErrorResult
// @Failure 404 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /carts/{id} [delete]
func (h *Handler) DeleteCart(c echo.Context) error {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id < 1 {
		return c.JSON(http.StatusBadRequest, dto.ErrorResult{
			Code:    http.StatusBadRequest,
			Message: "Invalid cart ID format",
		})
	}

	// Get authenticated user
	userID, ok := c.Get("userLogin").(int)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}

	// Check cart item exists and belongs to user
	cartItem, err := h.cartRepository.GetByID(uint(id))
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return c.JSON(http.StatusNotFound, dto.ErrorResult{
				Code:    http.StatusNotFound,
				Message: "Cart item not found",
			})
		}
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch cart item",
		})
	}

	// Check ownership (unless admin)
	isAdmin, _ := c.Get("isAdmin").(bool)
	if !isAdmin && cartItem.UserID != uint(userID) {
		return c.JSON(http.StatusForbidden, dto.ErrorResult{
			Code:    http.StatusForbidden,
			Message: "Forbidden: You don't have access to this cart item",
		})
	}

	if err := h.cartRepository.Delete(uint(id)); err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to delete cart item",
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: "Cart item deleted successfully",
	})
}

// GetUserCart godoc
// @Summary Get user's cart
// @Description Get all cart items for the authenticated user
// @Tags Cart
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.SuccessResult{data=[]dtoCart.CartResponse}
// @Failure 401 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /users/cart [get]
func (h *Handler) GetUserCart(c echo.Context) error {
	userID, ok := c.Get("userLogin").(int)
	if !ok {
		return c.JSON(http.StatusUnauthorized, dto.ErrorResult{
			Code:    http.StatusUnauthorized,
			Message: "Unauthorized",
		})
	}

	carts, err := h.cartRepository.GetByUserID(uint(userID))
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch user cart",
		})
	}

	var response []dtoCart.CartResponse
	for _, cartItem := range carts {
		response = append(response, dtoCart.CartResponse{
			ID:        cartItem.ID,
			UserID:    cartItem.UserID,
			ProductID: cartItem.ProductID,
			Quantity:  cartItem.Quantity,
			Product: dtoCart.Product{
				ID:       cartItem.Product.ID,
				Name:     cartItem.Product.Name,
				Price:    cartItem.Product.Price,
				Quantity: cartItem.Product.Quantity,
				BrandID:  cartItem.Product.BrandID,
			},
		})
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}

// GetAllCartsWithPagination godoc
// @Summary Get paginated carts (Admin)
// @Description Get paginated list of all cart items (Admin only)
// @Tags Cart
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1) minimum(1)
// @Param limit query int false "Items per page" default(10) minimum(1) maximum(100)
// @Success 200 {object} dto.SuccessResult{data=dtoCart.CartResponse}
// @Failure 400 {object} dto.ErrorResult
// @Failure 401 {object} dto.ErrorResult
// @Failure 403 {object} dto.ErrorResult
// @Failure 500 {object} dto.ErrorResult
// @Router /carts/paginate [get]
func (h *Handler) GetAllCartsWithPagination(c echo.Context) error {
	// Admin check
	isAdmin, ok := c.Get("isAdmin").(bool)
	if !ok || !isAdmin {
		return c.JSON(http.StatusForbidden, dto.ErrorResult{
			Code:    http.StatusForbidden,
			Message: "Forbidden: Admin access required",
		})
	}

	pageStr := c.QueryParam("page")
	limitStr := c.QueryParam("limit")

	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit < 1 {
		limit = 10
	} else if limit > 100 {
		limit = 100
	}

	carts, total, err := h.cartRepository.GetAllWithPagination(page, limit)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, dto.ErrorResult{
			Code:    http.StatusInternalServerError,
			Message: "Failed to fetch carts",
		})
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))

	// Map to response format
	var cartResponses []dtoCart.CartResponse
	for _, cartItem := range carts {
		cartResponses = append(cartResponses, dtoCart.CartResponse{
			ID:        cartItem.ID,
			UserID:    cartItem.UserID,
			ProductID: cartItem.ProductID,
			Quantity:  cartItem.Quantity,
			Product: dtoCart.Product{
				ID:       cartItem.Product.ID,
				Name:     cartItem.Product.Name,
				Price:    cartItem.Product.Price,
				Quantity: cartItem.Product.Quantity,
				BrandID:  cartItem.Product.BrandID,
			},
		})
	}

	response := struct {
		Carts      []dtoCart.CartResponse `json:"carts"`
		Total      int                    `json:"total"`
		Page       int                    `json:"page"`
		Limit      int                    `json:"limit"`
		TotalPages int                    `json:"total_pages"`
	}{
		Carts:      cartResponses,
		Total:      total,
		Page:       page,
		Limit:      limit,
		TotalPages: totalPages,
	}

	return c.JSON(http.StatusOK, dto.SuccessResult{
		Code: http.StatusOK,
		Data: response,
	})
}
