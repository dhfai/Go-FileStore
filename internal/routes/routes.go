package routes

import (
	"github.com/dhfai/Go-FileStore.git/internal/controllers"
	"github.com/dhfai/Go-FileStore.git/internal/middleware"
	"github.com/dhfai/Go-FileStore.git/internal/services"
	"github.com/gin-gonic/gin"
)

// SetupRoutes configures all application routes
func SetupRoutes(
	router *gin.Engine,
	authController *controllers.AuthController,
	profileController *controllers.ProfileController,
	authService *services.AuthService,
) {
	// Health check endpoint (no middleware needed)
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "file-store-api",
			"version": "1.0.0",
		})
	})

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Public routes (no authentication required)
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authController.Register)
			auth.POST("/login", authController.Login)
			auth.POST("/forget-password", authController.ForgetPassword)
			auth.POST("/reset-password", authController.ResetPassword)
		}

		// Protected routes (authentication required)
		protected := v1.Group("/")
		protected.Use(middleware.AuthMiddleware(authService))
		{
			// User profile routes
			profile := protected.Group("/profile")
			{
				profile.GET("/", profileController.GetProfile)
				profile.PUT("/", profileController.UpdateProfile)
				profile.DELETE("/", profileController.DeleteProfile)
			}

			// User info routes
			user := protected.Group("/user")
			{
				user.GET("/info", profileController.GetUserInfo)
			}
		}
	}
}

// SetupMiddleware configures all middleware
func SetupMiddleware(router *gin.Engine) {
	// Request ID middleware (first to set request ID for all requests)
	router.Use(middleware.RequestIDMiddleware())

	// Logger middleware (after request ID)
	router.Use(middleware.LoggerMiddleware())

	// Error handling middleware
	router.Use(middleware.ErrorHandlerMiddleware())

	// Security headers middleware
	router.Use(middleware.SecurityHeadersMiddleware())

	// CORS middleware
	router.Use(middleware.CORSMiddleware())

	// Rate limiting middleware (optional)
	router.Use(middleware.RateLimitMiddleware())
}
