package handlers

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"time"
	"strings"

	db "github.com/LuisAcerv/goeth-api/db"
	"github.com/aidarkhanov/nanoid/v2"
	"github.com/golang-jwt/jwt"
	"golang.org/x/crypto/bcrypt"

	Models "github.com/LuisAcerv/goeth-api/models"
	Modules "github.com/LuisAcerv/goeth-api/modules"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gorilla/mux"
)

// ClientHandler ethereum client instance
type ClientHandler struct {
	*ethclient.Client
}

func GeneratehashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func ValidateEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	return true
}

func GenerateJWT(email, role string) (string, error) {
	var mySigningKey = []byte("secretkey")
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)

	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	return tokenString, nil
}

func CheckPasswordHash(password string, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func ValidateToken(loginJWTToken string) (role string, err error) {

	var mySigningKey = []byte("secretkey")

	token, err := jwt.ParseWithClaims(
		loginJWTToken,
		&Models.JWTClaim{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(mySigningKey), nil
		},
	)
	if err != nil {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	claims, ok := token.Claims.(*Models.JWTClaim)

	if !ok {
		fmt.Errorf("Something Went Wrong: %s", err.Error())
		return "", err
	}
	if claims.ExpiresAt < time.Now().Local().Unix() {
		fmt.Errorf("Token has expired: %s", err.Error())
		return "", err
	}
	return "role", nil
}

func (client ClientHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Get parameter from url request
	vars := mux.Vars(r)
	module := vars["module"]

	// Get the query parameters from url request
	address := r.URL.Query().Get("address")
	hash := r.URL.Query().Get("hash")
	method := r.Method

	// Set our response header
	w.Header().Set("Content-Type", "application/json")

	// Handle each request using the module parameter:
	switch module {
	case "latest-block":
		_block := Modules.GetLatestBlock(*client.Client)
		json.NewEncoder(w).Encode(_block)

	case "get-tx":
		if hash == "" {
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Malformed request",
			})
			return
		}
		txHash := common.HexToHash(hash)
		_tx := Modules.GetTxByHash(*client.Client, txHash)

		if _tx != nil {
			json.NewEncoder(w).Encode(_tx)
			return
		}

		json.NewEncoder(w).Encode(&Models.Response{
			Code:    404,
			Message: "Tx Not Found!",
		})

	case "send-eth":
		decoder := json.NewDecoder(r.Body)
		var t Models.TransferEthRequest

		err := decoder.Decode(&t)

		if err != nil {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Malformed request",
			})
			return
		}
		_hash, err := Modules.TransferEth(*client.Client, t.PrivKey, t.To, t.Amount)

		if err != nil {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Internal server error",
			})
			return
		}

		json.NewEncoder(w).Encode(&Models.HashResponse{
			Hash: _hash,
		})

	case "get-balance":
		JWTToken := r.Header.Get("Authorization")
		TokenArray := strings.Split(JWTToken, " ");
		if TokenArray[1] == "" {
			fmt.Println("No JWT Token found")
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "No JWT Token found",
			})
			return
		}
		role, err := ValidateToken(TokenArray[1])
		if err != nil {
			fmt.Println("JWT Token error", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "JWT Token err",
			})
			return
		}

		if role != "manufacturer" {
			fmt.Println("User role err", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "User role err",
			})
			return
		}

		if method == "GET" {
			if address == "" {
				json.NewEncoder(w).Encode(&Models.Response{
					Code:    400,
					Message: "Malformed request",
				})
				return
			}

			balance, err := Modules.GetAddressBalance(*client.Client, address)

			if err != nil {
				fmt.Println(err)
				json.NewEncoder(w).Encode(&Models.Response{
					Code:    500,
					Message: "Internal server error",
				})
				return
			}

			json.NewEncoder(w).Encode(&Models.BalanceResponse{
				Address: address,
				Balance: balance,
				Symbol:  "Ether",
				Units:   "Wei",
			})

		} else {
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Internal server error",
			})
			return
		}
	case "sign-up":
		var signUpUser Models.SignUpUser
		var dbUser Models.DBUser
		var err error

		err = json.NewDecoder(r.Body).Decode(&signUpUser)
		if err != nil {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Malformed request",
			})
			return
		}

		isEmailValid := ValidateEmail(signUpUser.Email)
		if !isEmailValid {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Email not in the correct format",
			})
			return
		}

		row := db.DB.QueryRow("SELECT * FROM users where email= $1", signUpUser.Email)
		err = row.Scan(&dbUser.ID, &dbUser.Name, &dbUser.Username, &dbUser.Email, &dbUser.Passhash, &dbUser.Role)

		if err != nil && err != sql.ErrNoRows {
			fmt.Println("Error querying DB for users", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Error querying DB for users",
			})
			return
		}

		//checks if email is already register
		if dbUser.Email != "" {
			fmt.Println("Email already in use", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Email already in use",
			})
			return
		}

		var newUser = new(Models.DBUser)
		//create newUser details
		newUser.Passhash, err = GeneratehashPassword(signUpUser.Password)
		if err != nil {
			log.Fatalln("error in password hash creation")
		}

		//register new user
		fmt.Println("New User Registration")
		newUser.ID, err = nanoid.New()
		if err != nil {
			fmt.Println("Error generating UUID", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Error generating UUID",
			})
			return
		}

		_, err = db.DB.Exec("INSERT INTO users(id, name,username, email, passhash, role) VALUES ($1,$2, $3, $4, $5, $6)", newUser.ID, signUpUser.Name, newUser.Username, signUpUser.Email, newUser.Passhash, signUpUser.Role)
		if err != nil {
			fmt.Println("Error inserting new user to DB", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Error inserting new user to DB",
			})
			return
		}
		fmt.Println("New User Registration Successful")
		json.NewEncoder(w).Encode(&Models.Response{
			Code:    200,
			Message: "New User Registration Successful",
		})
		return
	case "sign-in":
		var loginDetails *Models.LogInUserDetails
		var dbUser Models.DBUser

		err := json.NewDecoder(r.Body).Decode(&loginDetails)
		if err != nil {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Malformed request",
			})
			return
		}
		isEmailValid := ValidateEmail(loginDetails.Email)
		if !isEmailValid {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Email not in the correct format",
			})
			return
		}

		row := db.DB.QueryRow("SELECT * FROM users where email= $1", loginDetails.Email)
		err = row.Scan(&dbUser.ID, &dbUser.Name, &dbUser.Username, &dbUser.Email, &dbUser.Passhash, &dbUser.Role)

		if err != nil && err != sql.ErrNoRows {
			fmt.Println("Error querying DB for users", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Error querying DB for users",
			})
			return
		}

		//checks if email is registered
		if dbUser.Email == "" {
			fmt.Println(err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Email not registered. Please sign-up",
			})
			return
		}

		check := CheckPasswordHash(loginDetails.Password, dbUser.Passhash)

		if !check {
			fmt.Println("Username or Password is Incorrect", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    400,
				Message: "Username or Password is Incorrect",
			})
			return
		}

		validToken, err := GenerateJWT(dbUser.Email, dbUser.Role)
		if err != nil {
			fmt.Println("Error generating JWT token", err)
			json.NewEncoder(w).Encode(&Models.Response{
				Code:    500,
				Message: "Error generating JWT token",
			})
			return
		}

		var token Models.Token
		token.Email = dbUser.Email
		token.Role = dbUser.Role
		token.TokenString = validToken
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(token)
	}
}
