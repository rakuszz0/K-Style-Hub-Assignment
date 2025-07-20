package models

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	ID        int    `json:"id" gorm:"primaryKey"`
	FirstName string `json:"first_name" form:"first_name"`
	LastName  string `json:"last_name" form:"last_name"`
	Username  string `json:"username" form:"username" gorm:"unique"`
	Phone     string `json:"phone" form:"phone" gorm:"unique"`
	Address   string `json:"address,omitempty" form:"address"`
	Email     string `json:"email" form:"email" gorm:"unique"`
	Password  string `json:"_" form:"password"`
	IsAdmin   bool   `json:"isAdmin" form:"isAdmin"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type UserResponseJWT struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Phone    string `json:"phone" form:"phone"`
	Address  string `json:"address" form:"address"`
	Token    string `json:"token"`
	IsAdmin  bool   `json:"isAdmin" form:"isAdmin"`
}

type Brand struct {
	ID       uint      `json:"id" gorm:"primaryKey"`
	Name     string    `json:"name" form:"name"`
	Products []Product `json:"products" gorm:"foreignKey:BrandID"`
}

type Product struct {
	ID       uint    `json:"id" gorm:"primaryKey"`
	Name     string  `json:"name" form:"name"`
	Price    float64 `json:"price" form:"price"`
	Quantity int     `json:"quantity" form:"quantity"`
	BrandID  uint    `json:"brand_id" form:"brand_id"`
}

type Cart struct {
	ID        uint    `json:"id" gorm:"primaryKey"`
	UserID    uint    `json:"user_id" form:"user_id"`
	ProductID uint    `json:"product_id" form:"product_id"`
	Quantity  int     `json:"quantity" form:"quantity"`
	User      User    `json:"user" form:"user" gorm:"foreignKey:UserID"`
	Product   Product `json:"product" form:"product" gorm:"foreignKey:ProductID"`
}

type Order struct {
	ID        uint    `json:"id" gorm:"primaryKey"`
	UserID    uint    `json:"user_id" form:"user_id"`
	ProductID uint    `json:"product_id" form:"product_id"`
	Quantity  int     `json:"quantity" form:"quantity"`
	Status    string  `json:"status" form:"status" gorm:"default:'pending'"`
	User      User    `json:"user" form:"user" gorm:"foreignKey:UserID"`
	Product   Product `json:"product" form:"product" gorm:"foreignKey:ProductID"`
}

// type Transaction struct {
// 	ID        uint    `json:"id" gorm:"primaryKey"`
// 	UserID    uint    `json:"user_id" form:"user_id"`
// 	ProductID uint    `json:"product_id" form:"product_id"`
// 	Quantity  int     `json:"quantity" form:"quantity"`
// 	User      User    `json:"user" form:"user" gorm:"foreignKey:UserID"`
// 	Product   Product `json:"product" form:"product" gorm:"foreignKey:ProductID"`
// 	Status    string  `json:"status" form:"status" gorm:"default:'pending'`
// }
