package service

import (
	"github.com/jinzhu/gorm"
	"os"
	"fmt"
)

var DB DBConnect

type DBConnect struct {
	Connect *gorm.DB
}

func (db *DBConnect) Init() error  {

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

	db.Connect = c

	fmt.Println("Db Connect Successfully...")

	return nil
}
