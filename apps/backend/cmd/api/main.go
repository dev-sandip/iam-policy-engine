package main

import (
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	e := echo.New()
	e.GET("/", func(c echo.Context) error {
		log.Print("hello world")
		log.Print("Hello Sandip Live Reload")
		return c.String(http.StatusOK, "Welcome to IAM Policy Engine API")
	})

	e.Logger.Fatal(e.Start(":1323"))
}
