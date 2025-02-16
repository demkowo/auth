package app

import (
	"log"
	"os"

	"github.com/demkowo/auth/config"
	handler "github.com/demkowo/auth/handlers"
	"github.com/demkowo/auth/repositories/postgres"
	service "github.com/demkowo/auth/services"
	dbclient "github.com/demkowo/dbclient/client"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

var (
	dbConnection = os.Getenv("DB_CLIENT")
	router       = gin.Default()
	cfg          = config.Values.Get()
)

func Start() {
	db, err := dbclient.Open("postgres", dbConnection)
	if err != nil {
		log.Panic(err)
	}
	defer db.Close()

	accountRepo := postgres.NewAccount(db)
	accountService := service.NewAccount(accountRepo)
	accountHandler := handler.NewAccount(accountService)
	addAccountRoutes(router, accountHandler, accountService)

	err = accountRepo.CreateTables()
	if err != nil {
		log.Panic(err)
	}

	router.Run(cfg.Port)
}
