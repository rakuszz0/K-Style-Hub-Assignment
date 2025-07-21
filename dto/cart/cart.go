package cart

import (
	"time"

	"gorm.io/gorm"
)

type CartRequest struct {
	ProductID uint `json:"product_id" form:"product_id"`
	Quantity  int  `json:"quantity" form:"quantity"`
}

type CartResponse struct {
	ID        uint           `json:"id"`
	UserID    uint           `json:"user_id"`
	ProductID uint           `json:"product_id"`
	Quantity  int            `json:"quantity"`
	Product   Product        `json:"product"`
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
