package db

import "database/sql"

var DB *sql.DB

func ConnectDB() error {
	var err error

	connStr := "host=localhost port=5432 dbname=luxury_items user=postgres password=test connect_timeout=10 sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return err
	}
	DB = db
	return nil
}

func Close() error {
	return DB.Close()
}
