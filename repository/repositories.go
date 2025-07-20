package repositories

import (
	"ecommerce/models"
	"errors"

	"gorm.io/gorm"
)

// ============User Repository============

type UserRepository interface {
	Create(user *models.User) error
	GetAll() ([]models.User, error)
	GetByID(id uint) (*models.User, error)
	Update(user *models.User) error
	Delete(id uint) error
	GetByEmail(email string) (*models.User, error)
	GetByUsername(username string) (*models.User, error)
	GetAllWithPagination(page, limit int) ([]models.User, int, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

func (r *userRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

func (r *userRepository) GetAll() ([]models.User, error) {
	var users []models.User
	err := r.db.Find(&users).Error
	return users, err
}

func (r *userRepository) GetByID(id uint) (*models.User, error) {
	var user models.User
	err := r.db.First(&user, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &user, nil
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
	var user models.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) GetByUsername(username string) (*models.User, error) {
	var user models.User
	err := r.db.Where("username = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *userRepository) Update(user *models.User) error {
	return r.db.Save(user).Error
}

func (r *userRepository) Delete(id uint) error {
	return r.db.Delete(&models.User{}, id).Error
}

func (r *userRepository) GetAllWithPagination(page, limit int) ([]models.User, int, error) {
	var users []models.User
	var total int64

	offset := (page - 1) * limit

	err := r.db.Model(&models.User{}).
		Count(&total).
		Limit(limit).
		Offset(offset).
		Find(&users).Error

	if err != nil {
		return nil, 0, err
	}

	return users, int(total), nil
}

// ============Brand Repository============

type BrandRepository interface {
	Create(brand *models.Brand) error
	GetAll() ([]models.Brand, error)
	GetByID(id uint) (models.Brand, error)
	Update(brand *models.Brand) error
	Delete(id uint) error
}

type brandRepository struct {
	db *gorm.DB
}

func NewBrandRepository(db *gorm.DB) BrandRepository {
	return &brandRepository{db: db}
}

func (r *brandRepository) Create(brand *models.Brand) error {
	return r.db.Create(brand).Error
}

func (r *brandRepository) GetAll() ([]models.Brand, error) {
	var brands []models.Brand
	err := r.db.Preload("Products").Find(&brands).Error
	return brands, err
}

func (r *brandRepository) GetByID(id uint) (models.Brand, error) {
	var brand models.Brand
	err := r.db.Preload("Products").First(&brand, id).Error
	return brand, err
}

func (r *brandRepository) Update(brand *models.Brand) error {
	return r.db.Save(brand).Error
}

func (r *brandRepository) Delete(id uint) error {
	return r.db.Delete(&models.Brand{}, id).Error
}

// ============Product Repository============

type ProductRepository interface {
	Create(product *models.Product) error
	GetAll() ([]models.Product, error)
	GetByID(id uint) (*models.Product, error)
	Update(product *models.Product) error
	Delete(id uint) error
	GetByBrandID(brandID uint) ([]models.Product, error)
	GetAllWithPagination(page, limit int) ([]models.Product, int, error)
}

type productRepository struct {
	db *gorm.DB
}

func NewProductRepository(db *gorm.DB) ProductRepository {
	return &productRepository{db: db}
}

func (r *productRepository) Create(product *models.Product) error {
	return r.db.Create(product).Error
}

func (r *productRepository) GetAll() ([]models.Product, error) {
	var products []models.Product
	err := r.db.Find(&products).Error
	return products, err
}

func (r *productRepository) GetByID(id uint) (*models.Product, error) {
	var product models.Product
	err := r.db.First(&product, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &product, err
}

func (r *productRepository) Update(product *models.Product) error {
	return r.db.Save(product).Error
}

func (r *productRepository) Delete(id uint) error {
	return r.db.Delete(&models.Product{}, id).Error
}

func (r *productRepository) GetByBrandID(brandID uint) ([]models.Product, error) {
	var products []models.Product
	err := r.db.Where("brand_id = ?", brandID).Find(&products).Error
	return products, err
}

func (r *productRepository) GetAllWithPagination(page, limit int) ([]models.Product, int, error) {
	var products []models.Product
	var total int64

	offset := (page - 1) * limit

	err := r.db.Model(&models.Product{}).
		Count(&total).
		Limit(limit).
		Offset(offset).
		Find(&products).Error
	if err != nil {
		return nil, 0, err
	}

	return products, int(total), nil
}

type CartRepository interface {
	Create(cart *models.Cart) error
	GetAll() ([]models.Cart, error)
	GetByID(id uint) (*models.Cart, error)
	Update(cart *models.Cart) error
	Delete(id uint) error
	GetByUserID(userID uint) ([]models.Cart, error)
	GetByUserIDAndProductID(userID, productID uint) (*models.Cart, error)
	GetAllWithPagination(page, limit int) ([]models.Cart, int, error)
}

type cartRepository struct {
	db *gorm.DB
}

func NewCartRepository(db *gorm.DB) CartRepository {
	return &cartRepository{db: db}
}

func (r *cartRepository) Create(cart *models.Cart) error {
	return r.db.Create(cart).Error
}

func (r *cartRepository) GetAll() ([]models.Cart, error) {
	var carts []models.Cart
	err := r.db.Preload("User").Preload("Product").Find(&carts).Error
	return carts, err
}

func (r *cartRepository) GetByID(id uint) (*models.Cart, error) {
	var cart models.Cart
	err := r.db.Preload("User").Preload("Product").First(&cart, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &cart, err
}

func (r *cartRepository) Update(cart *models.Cart) error {
	return r.db.Save(cart).Error
}

func (r *cartRepository) Delete(id uint) error {
	return r.db.Delete(&models.Cart{}, id).Error
}

func (r *cartRepository) GetByUserID(userID uint) ([]models.Cart, error) {
	var carts []models.Cart
	err := r.db.Where("user_id = ?", userID).Preload("Product").Find(&carts).Error
	return carts, err
}

func (r *cartRepository) GetByUserIDAndProductID(userID, productID uint) (*models.Cart, error) {
	var cart models.Cart
	err := r.db.Where("user_id = ? AND product_id = ?", userID, productID).First(&cart).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &cart, err
}

func (r *cartRepository) GetAllWithPagination(page, limit int) ([]models.Cart, int, error) {
	var carts []models.Cart
	var total int64

	offset := (page - 1) * limit

	err := r.db.Model(&models.Cart{}).
		Count(&total).
		Limit(limit).
		Offset(offset).
		Preload("User").
		Preload("Product").
		Find(&carts).Error
	if err != nil {
		return nil, 0, err
	}

	return carts, int(total), nil
}

type OrderRepository interface {
	Create(order *models.Order) error
	GetAll() ([]models.Order, error)
	GetByID(id uint) (*models.Order, error)
	Update(order *models.Order) error
	Delete(id uint) error
	GetByUserID(userID uint) ([]models.Order, error)
	GetAllWithPagination(page, limit int) ([]models.Order, int, error)
}

type orderRepository struct {
	db *gorm.DB
}

func NewOrderRepository(db *gorm.DB) OrderRepository {
	return &orderRepository{db: db}
}

func (r *orderRepository) Create(order *models.Order) error {
	return r.db.Create(order).Error
}

func (r *orderRepository) GetAll() ([]models.Order, error) {
	var orders []models.Order
	err := r.db.Preload("User").Preload("Product").Find(&orders).Error
	return orders, err
}

func (r *orderRepository) GetByID(id uint) (*models.Order, error) {
	var order models.Order
	err := r.db.Preload("User").Preload("Product").First(&order, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &order, err
}

func (r *orderRepository) Update(order *models.Order) error {
	return r.db.Save(order).Error
}

func (r *orderRepository) Delete(id uint) error {
	return r.db.Delete(&models.Order{}, id).Error
}

func (r *orderRepository) GetByUserID(userID uint) ([]models.Order, error) {
	var orders []models.Order
	err := r.db.Where("user_id = ?", userID).Preload("Product").Find(&orders).Error
	return orders, err
}

func (r *orderRepository) GetAllWithPagination(page, limit int) ([]models.Order, int, error) {
	var orders []models.Order
	var total int64

	offset := (page - 1) * limit

	err := r.db.Model(&models.Order{}).
		Count(&total).
		Limit(limit).
		Offset(offset).
		Preload("User").
		Preload("Product").
		Find(&orders).Error
	if err != nil {
		return nil, 0, err
	}

	return orders, int(total), nil
}
