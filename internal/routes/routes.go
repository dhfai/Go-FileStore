package routes

import (
	"github.com/dhfai/Go-FileStore.git/internal/controllers"
	"github.com/dhfai/Go-FileStore.git/internal/middleware"
	"github.com/dhfai/Go-FileStore.git/internal/services"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// SetupRoutes configures all application routes
func SetupRoutes(
	router *gin.Engine,
	authController *controllers.AuthController,
	profileController *controllers.ProfileController,
	authService *services.AuthService,
	db *gorm.DB,
) {
	router.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status":  "ok",
			"service": "file-store-api",
			"version": "1.0.0",
		})
	})

	v1 := router.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authController.Register)
			auth.POST("/login", authController.Login)
			auth.POST("/verify-email", authController.VerifyEmail)
			auth.POST("/resend-verification", authController.ResendVerification)
			auth.POST("/forget-password", authController.ForgetPassword)
			auth.POST("/reset-password", authController.ResetPassword)
		}

		protected := v1.Group("/")
		protected.Use(middleware.AuthMiddleware(authService, db))
		{
			// Auth protected endpoints
			auth := protected.Group("/auth")
			{
				auth.POST("/logout", authController.Logout)
				auth.POST("/request-delete-account", authController.RequestDeleteAccount)
				auth.POST("/delete-account", authController.DeleteAccount)
			}

			profile := protected.Group("/profile")
			{
				profile.GET("", profileController.GetProfile)
				profile.PUT("", profileController.UpdateProfile)
				profile.DELETE("", profileController.DeleteProfile)
			}

			user := protected.Group("/user")
			{
				user.GET("/info", profileController.GetUserInfo)
			}
		}
	}
}

// SetupMiddleware configures all middleware
func SetupMiddleware(router *gin.Engine) {
	router.Use(middleware.RequestIDMiddleware())
	router.Use(middleware.LoggerMiddleware())
	router.Use(middleware.ErrorHandlerMiddleware())
	router.Use(middleware.SecurityHeadersMiddleware())
	router.Use(middleware.CORSMiddleware())
	router.Use(middleware.RateLimitMiddleware())
}
