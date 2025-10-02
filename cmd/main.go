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
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize logger
	logger.InitLogger(cfg.App.Environment)
	log := logger.GetLogger()

	log.Info("Starting File Store API server...")
	log.WithField("environment", cfg.App.Environment).Info("Configuration loaded")

	// Initialize database
	database, err := config.NewDatabase(cfg)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	defer database.Close()

	// Run database migrations
	if err := database.Migrate(); err != nil {
		log.WithError(err).Fatal("Failed to run database migrations")
	}

	// Initialize services
	authService := services.NewAuthService(cfg.JWT.Secret)
	emailService := services.NewEmailService(&cfg.Email)

	// Initialize controllers
	authController := controllers.NewAuthController(database.DB, authService, emailService)
	profileController := controllers.NewProfileController(database.DB)

	// Set Gin mode based on environment
	if cfg.App.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	// Initialize Gin router
	router := gin.New()

	// Setup middleware
	routes.SetupMiddleware(router)

	// Setup routes
	routes.SetupRoutes(router, authController, profileController, authService)

	// Server address
	serverAddr := fmt.Sprintf("%s:%s", cfg.Server.Host, cfg.Server.Port)

	log.WithField("address", serverAddr).Info("Server starting...")

	// Start server in a goroutine
	go func() {
		if err := router.Run(serverAddr); err != nil {
			log.WithError(err).Fatal("Failed to start server")
		}
	}()

	log.WithField("address", serverAddr).Info("Server started successfully")
	log.Info("🚀 File Store API is ready to accept requests!")

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down server...")

	// Perform cleanup
	log.Info("Server shutdown complete")
}
