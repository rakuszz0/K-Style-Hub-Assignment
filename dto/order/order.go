package order

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
}

type Product struct {
	ID       uint    `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
	BrandID  uint    `json:"brand_id"`
}
