package service

import (
	"github.com/jinzhu/gorm"
	"os"
	"fmt"
)

type DB struct {
	Connect *gorm.DB
}

func (db *DB) Init() error  {

	c, err := gorm.Open(
		"postgres",
		"host="+os.Getenv("DB_HOST") +
		" port="+os.Getenv("DB_PORT") +
		" user="+os.Getenv("DB_USER") +
		" dbname="+os.Getenv("DB_NAME") +
		" password="+os.Getenv("DB_PSW"))

	if err != nil {
		return err
	}
	fmt.Println("Starting the application...")
	db.Connect = c
	return nil
}
