package auth

import "time"

// --- Request DTOs ---

// SignUpRequest digunakan saat donatur atau admin mendaftar

type SignUpRequest struct {
	FirstName string `json:"first_name" validate:"required,min=2,max=50"`
	LastName  string `json:"last_name" validate:"required,min=2,max=50"`
	Username  string `json:"username" validate:"required,min=3,max=20,alphanum"`
	Phone     string `json:"phone" validate:"required,e164"` // Format E.164: +6281234567890
	Address   string `json:"address" validate:"max=255"`     // Opsional
	Email     string `json:"email" validate:"required,email,max=100"`
	Password  string `json:"password" validate:"required,min=8,max=72,containsany=!@#$%^&*,containsuppercase,containsnumber"`
}

// SignInRequest digunakan saat user login
// @Example {"email":"test@example.com", "password":"SecurePass123!"}
type SignInRequest struct {
	Value    string `json:"value" validate:"required,min=3,max=100"`
	Password string `json:"password" validate:"required,min=8,max=72"`
}

// ChangePasswordRequest digunakan saat user mengganti password
// @Example {"old_password":"OldPass123!", "new_password":"NewPass456!"}
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" validate:"required"`
	NewPassword string `json:"new_password" validate:"required,min=8,max=72,containsany=!@#$%^&*,containsuppercase,containsnumber,nefield=OldPassword"`
}

// --- Response DTOs ---

// BaseResponse struktur dasar untuk semua response
type BaseResponse struct {
	Success   bool        `json:"success"`
	Message   string      `json:"message,omitempty"`
	Data      interface{} `json:"data,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// AuthData struktur data auth untuk response
type AuthData struct {
	ID        uint   `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	Phone     string `json:"phone"`
	Address   string `json:"address,omitempty"`
	Email     string `json:"email"`
	IsAdmin   bool   `json:"isAdmin"`
	Token     string `json:"token"`
}

// AuthResponse digunakan untuk response setelah login atau signup
func NewAuthResponse(message string, authData AuthData) BaseResponse {
	return BaseResponse{
		Success:   true,
		Message:   message,
		Data:      authData,
		Timestamp: time.Now(),
	}
}

// ErrorResponse digunakan untuk response error
func ErrorResponse(code int, message string) BaseResponse {
	return BaseResponse{
		Success:   false,
		Message:   message,
		Timestamp: time.Now(),
	}
}

// MessageResponse digunakan untuk respons umum
func MessageResponse(message string) BaseResponse {
	return BaseResponse{
		Success:   true,
		Message:   message,
		Timestamp: time.Now(),
	}
}
