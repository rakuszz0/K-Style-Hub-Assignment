package database

import (
	"ecommerce/models"
	"ecommerce/pkg/mysql"
	"fmt"
)

func RunMigration() {
	err := mysql.DB.AutoMigrate(
		&models.User{},
		&models.Brand{},
		&models.Product{},
		&models.Order{},
		&models.Cart{},
	)

	if err != nil {
		fmt.Println(err)
		panic("Migration Failed")
	}

	fmt.Println("Migration Success")
}
