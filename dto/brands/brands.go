package brands

import (
	"time"

	"gorm.io/gorm"
)

type BrandRequest struct {
	Name string `json:"name" form:"name" gorm:"unique"`
}

type BrandResponse struct {
	ID       uint                   `json:"id"`
	Name     string                 `json:"name"`
	Products []BrandProductResponse `json:"products"`

	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

type BrandProductResponse struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
}
