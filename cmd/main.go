package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type UsersPayload struct {
	Users []User `json:"users"`
}

type MessagePayload struct {
	Message string `json:"message"`
}

var database = make(map[string]User)
var tokenAuth *jwtauth.JWTAuth

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 4)

	if err != nil {
		return string(hash), err
	}

	return string(hash), nil
}

func IsValidatePassword(hashed string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password))
	return err == nil
}

func GenerateAuthToken(tokenAuth *jwtauth.JWTAuth, token map[string]interface{}) (string, error) {
	_, tokenString, err := tokenAuth.Encode(token)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	var ENV = os.Getenv("ENV")
	var JWT_SECRET = os.Getenv("JWT_SECRET")
	tokenAuth = jwtauth.New("HS256", []byte(JWT_SECRET), nil)

	router := chi.NewRouter()
	router.Use(middleware.Logger)
	router.Use(render.SetContentType(render.ContentTypeJSON))

	router.Get("/", func(w http.ResponseWriter, r *http.Request) {
		payload := MessagePayload{Message: "Server Working!"}
		render.JSON(w, r, payload)
	})

	router.Post("/signup", func(w http.ResponseWriter, r *http.Request) {
		user := User{}

		err := json.NewDecoder(r.Body).Decode(&user)

		if err != nil || user.Email == "" || user.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			payload := MessagePayload{Message: "Please provide valid credentials"}
			render.JSON(w, r, payload)
			return
		}

		if database[user.Email].Email != "" {
			w.WriteHeader(http.StatusBadRequest)
			payload := MessagePayload{
				Message: fmt.Sprintf("User with email <%s> already exist", user.Email),
			}
			render.JSON(w, r, payload)
			return
		}

		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			payload := MessagePayload{
				Message: "Failed to hash the password",
			}
			render.JSON(w, r, payload)
			return
		}

		user.Password = hashedPassword
		database[user.Email] = user
		render.JSON(w, r, user)
	})

	router.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		credentials := User{}

		err := json.NewDecoder(r.Body).Decode(&credentials)
		if err != nil || credentials.Email == "" || credentials.Password == "" {
			w.WriteHeader(http.StatusBadRequest)
			payload := MessagePayload{Message: "Please provide valid credentials"}
			render.JSON(w, r, payload)
			return
		}

		user := database[credentials.Email]
		if user.Email == "" {
			w.WriteHeader(http.StatusNotFound)
			payload := MessagePayload{
				Message: fmt.Sprintf("User with email <%s> has not been found", credentials.Email),
			}
			render.JSON(w, r, payload)
			return
		}

		isValidPassword := IsValidatePassword(user.Password, credentials.Password)
		if !isValidPassword {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Println(user.Password)
			fmt.Println(credentials.Password)
			payload := MessagePayload{Message: "Invalid password provided"}
			render.JSON(w, r, payload)
			return
		}

		jwt, err := GenerateAuthToken(tokenAuth, map[string]interface{}{
			"email": user.Email,
			"exp":   time.Now().Unix() + 60*15,
		})

		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			payload := MessagePayload{
				Message: "Failed to generate auth token",
			}
			render.JSON(w, r, payload)
			return
		}

		cookie := http.Cookie{
			Name:     "jwt",
			Value:    jwt,
			MaxAge:   900,
			HttpOnly: ENV == "production",
			SameSite: http.SameSiteStrictMode,
			Secure:   ENV == "production",
		}

		http.SetCookie(w, &cookie)

		payload := MessagePayload{
			Message: fmt.Sprintf("User <%s> logged in successfully", user.Email),
		}

		render.JSON(w, r, payload)
	})

	router.Get("/users", func(w http.ResponseWriter, r *http.Request) {
		users := make([]User, 0)

		for _, user := range database {
			users = append(users, user)
		}

		payload := UsersPayload{Users: users}
		render.JSON(w, r, payload)
	})

	router.Get("/users/{email}", func(w http.ResponseWriter, r *http.Request) {
		email := chi.URLParam(r, "email")
		user := database[email]

		if user.Email == "" {
			w.WriteHeader(http.StatusBadRequest)
			payload := MessagePayload{
				Message: fmt.Sprintf("User with email <%s> has not been found", email),
			}
			render.JSON(w, r, payload)
			return
		}

		render.JSON(w, r, user)
	})

	router.Group(func(auth chi.Router) {
		auth.Use(jwtauth.Verifier(tokenAuth))
		auth.Use(jwtauth.Authenticator(tokenAuth))

		auth.Get("/auth/protected", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			payload := MessagePayload{Message: fmt.Sprintf("Welcome %s", claims["email"])}
			render.JSON(w, r, payload)
		})
	})

	http.ListenAndServe(":3000", router)
}
