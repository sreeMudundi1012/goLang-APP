package main

import (
	// "database/sql"
	"fmt"
	"log"
	"net/http"

	db "github.com/LuisAcerv/goeth-api/db"

	Handlers "github.com/LuisAcerv/goeth-api/handler"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

func main() {
	//Create an instance to connect to the postgres DB
	if err := db.ConnectDB(); err != nil {
		panic(err)
	}

	defer db.Close()
	err := db.DB.Ping()

	if err != nil {
		fmt.Println("Error connecting to database", err)
		panic(err)
	}
	fmt.Println("Successfully connected to database!")

	// Create a client instance to connect to our providr
	client, err := ethclient.Dial("http://localhost:7545")

	if err != nil {
		fmt.Println(err)
	}
	// Create a mux router
	r := mux.NewRouter()

	// We will define a single endpoint
	r.Handle("/api/v1/eth/{module}", Handlers.ClientHandler{client})
	fmt.Println("Successfully connected to localhost!")
	log.Fatal(http.ListenAndServe(":8080", r))
}
