package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/dhfai/Go-FileStore.git/internal/models"
	"github.com/dhfai/Go-FileStore.git/internal/services"
	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// AuthMiddleware validates JWT tokens and sets user context
func AuthMiddleware(authService *services.AuthService, db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		log := logger.GetLogger()

		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Warn("Missing Authorization header")
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Message: "Authorization header required",
			})
			c.Abort()
			return
		}

		// Check Bearer prefix
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			log.Warn("Invalid Authorization header format")
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Message: "Invalid authorization header format",
			})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// Check if token is blacklisted
		var blacklistCount int64
		if err := db.Model(&models.TokenBlacklist{}).Where("token = ? AND expires_at > ?", token, time.Now()).Count(&blacklistCount).Error; err == nil && blacklistCount > 0 {
			log.Warn("Blacklisted token used")
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Message: "Token has been revoked",
			})
			c.Abort()
			return
		}

		// Validate token
		claims, err := authService.ValidateToken(token)
		if err != nil {
			log.WithError(err).Warn("Invalid token")
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Message: "Invalid or expired token",
			})
			c.Abort()
			return
		}

		// Set user info in context
		userID, ok := claims["user_id"].(string)
		if !ok {
			log.Error("Invalid user_id in token claims")
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Message: "Invalid token claims",
			})
			c.Abort()
			return
		}

		email, ok := claims["email"].(string)
		if !ok {
			log.Error("Invalid email in token claims")
			c.JSON(http.StatusUnauthorized, models.APIResponse{
				Success: false,
				Message: "Invalid token claims",
			})
			c.Abort()
			return
		}

		// Set user info in context for use in handlers
		c.Set("user_id", userID)
		c.Set("email", email)

		log.WithField("user_id", userID).Debug("User authenticated successfully")
		c.Next()
	}
}
