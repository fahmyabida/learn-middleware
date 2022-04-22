package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// jwtCustomClaims are custom claims extending default ones.
// See https://github.com/golang-jwt/jwt for more examples
type jwtCustomClaims struct {
	Name   string `json:"name"`
	Admin  bool   `json:"admin"`
	Custom string `json:"custom"`
	jwt.StandardClaims
}

func login(c echo.Context) error {
	username := c.FormValue("username")
	password := c.FormValue("password")

	// Throws unauthorized error
	if username != "jon" || password != "shhh!" {
		return echo.ErrUnauthorized
	}

	// Set custom claims
	claims := &jwtCustomClaims{
		Name:   "Jon Snow",
		Admin:  true,
		Custom: "apa hayooo",
		StandardClaims: jwt.StandardClaims{
			Audience:  "",
			ExpiresAt: time.Now().Add(time.Hour * 72).Unix(),
			Id:        "",
			IssuedAt:  0,
			Issuer:    "",
			NotBefore: 0,
			Subject:   "",
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return err
	}

	return c.JSON(http.StatusOK, echo.Map{
		"token": t,
	})
}

func accessible(c echo.Context) error {
	return c.String(http.StatusOK, "Accessible")
}

func restricted(c echo.Context) error {
	user := c.Get("user").(*jwt.Token)
	claims := user.Claims.(*jwtCustomClaims)
	name := claims.Name
	return c.String(http.StatusOK, "Welcome "+name+"!"+claims.Custom)
}

func main() {
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Login route
	e.POST("/login", login) // 1

	// Unauthenticated route
	e.GET("/", accessible) // 2

	// Restricted group
	apiRestricted := e.Group("/restricted")

	// Configure middleware with the custom claims type
	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}
	apiRestricted.Use(middleware.JWTWithConfig(config))
	apiRestricted.GET("/terlarang", restricted) // 3
	apiRestricted.GET("/gaboleh", restricted)   // 4

	e.Logger.Fatal(e.Start(":8080"))
}
