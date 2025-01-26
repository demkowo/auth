package app

import (
	"database/sql"
	"log"
	"os"

	"github.com/gin-gonic/gin"

	handler "github.com/demkowo/auth/handlers"
	postgres "github.com/demkowo/auth/repositories"
	service "github.com/demkowo/auth/services"

	_ "github.com/lib/pq"
)

const (
	portNumber = ":5000"
)

var (
	dbConnection = os.Getenv("DB_CLIENT")
	router       = gin.Default()
)

func Start() {
	db, err := sql.Open("postgres", dbConnection)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	accountRepo := postgres.NewAccount(db)
	accountService := service.NewAccount(accountRepo)
	accountHandler := handler.NewAccount(accountService)
	addAccountRoutes(accountHandler)

	EnsureTablesExist(db)

	router.Run(portNumber)
}
