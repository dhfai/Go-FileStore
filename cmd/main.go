package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/dhfai/Go-FileStore.git/internal/config"
	"github.com/dhfai/Go-FileStore.git/internal/controllers"
	"github.com/dhfai/Go-FileStore.git/internal/routes"
	"github.com/dhfai/Go-FileStore.git/internal/services"
	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"github.com/gin-gonic/gin"
)

func main() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	logger.InitLogger(cfg.App.Environment)
	log := logger.GetLogger()

	log.Info("Starting File Store API server...")
	log.WithField("environment", cfg.App.Environment).Info("Configuration loaded")

	database, err := config.NewDatabase(cfg)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		log.WithError(err).Fatal("Failed to run database migrations")
	}

	authService := services.NewAuthService(cfg.JWT.Secret)
	emailService := services.NewEmailService(&cfg.Email)

	authController := controllers.NewAuthController(database.DB, authService, emailService)
	profileController := controllers.NewProfileController(database.DB)

	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	router := gin.New()

	router.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	routes.SetupMiddleware(router)

	routes.SetupRoutes(router, authController, profileController, authService, database.DB)

	serverAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	log.WithField("address", serverAddr).Info("Server starting...")

	go func() {
		if err := router.Run(serverAddr); err != nil {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()

	log.WithField("address", serverAddr).Info("Server started successfully")
	log.Info("🚀 File Store API is ready to accept requests!")

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	log.Info("Server shutdown complete")
}
