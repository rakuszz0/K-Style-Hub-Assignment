package order

import (
	"time"

	"gorm.io/gorm"
)

type OrderRequest struct {
	ProductID uint `json:"product_id" form:"product_id"`
	Quantity  int  `json:"quantity" form:"quantity"`
}

type OrderUpdateRequest struct {
	Quantity int    `json:"quantity" form:"quantity"`
	Status   string `json:"status" form:"status"`
}

type OrderResponse struct {
	ID        uint    `json:"id"`
	UserID    uint    `json:"user_id"`
	ProductID uint    `json:"product_id"`
	Quantity  int     `json:"quantity"`
	Product   Product `json:"product"`
	Status    string  `json:"status"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type Product struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
	BrandID  uint    `json:"brand_id"`
}
