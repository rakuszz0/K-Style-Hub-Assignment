package product

type ProductRequest struct {
	Name     string  `json:"name" form:"name"`
	Price    float64 `json:"price" form:"price"`
	Quantity int     `json:"quantity" form:"quantity"`
	BrandID  uint    `json:"brand_id" form:"brand_id"`
}

type ProductResponse struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
	BrandID  uint    `json:"brand_id"`
}
