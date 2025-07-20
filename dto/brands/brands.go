package brands

type BrandRequest struct {
	Name string `json:"name" form:"name" gorm:"unique"`
}

type BrandResponse struct {
	ID       uint                   `json:"id"`
	Name     string                 `json:"name"`
	Products []BrandProductResponse `json:"products"`
}

type BrandProductResponse struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
}
