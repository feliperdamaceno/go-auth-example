package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SimplePayload struct {
	Message string `json:"message"`
}

type Database = map[string]User

var database = make(Database)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4)

	if err != nil {
		return string(hash), err
	}

	return string(hash), nil
}

func ValidatePassword(hashed string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	return err == nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// var JWT_SECRET = os.Getenv("JWT_SECRET")

	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(render.SetContentType(render.ContentTypeJSON))

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		payload := SimplePayload{Message: "Server Working!"}
		render.JSON(w, r, payload)
	})

	router.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
		user := User{}

		err := json.NewDecoder(r.Body).Decode(&user)

		if err != nil || user.Email == "" || user.Password == "" {
			w.WriteHeader(400)
			payload := SimplePayload{Message: "Please provide valid credentials"}
			render.JSON(w, r, payload)
			return
		}

		if database[user.Email].Email != "" {
			w.WriteHeader(400)
			payload := SimplePayload{
				Message: fmt.Sprintf("User with email <%s> already exist", user.Email),
			}
			render.JSON(w, r, payload)
			return
		}

		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			w.WriteHeader(500)
			payload := SimplePayload{
				Message: "Failed to hash the password",
			}
			render.JSON(w, r, payload)
			return
		}

		user.Password = hashedPassword
		database[user.Email] = user
		render.JSON(w, r, user)
	})

	router.Post("/login", func(w http.ResponseWriter, r *http.Request) {})

	router.Get("/users", func(w http.ResponseWriter, r *http.Request) {
		users := make([]User, 0)

		for _, user := range database {
			users = append(users, user)
		}

		payload := struct {
			Users []User `json:"users"`
		}{
			Users: users,
		}

		render.JSON(w, r, payload)
	})

	router.Get("/users/{email}", func(w http.ResponseWriter, r *http.Request) {})

	http.ListenAndServe(":3000", router)
}
