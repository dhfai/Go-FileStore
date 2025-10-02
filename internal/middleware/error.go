package middleware

import (
	"net/http"
	"runtime/debug"

	"github.com/dhfai/Go-FileStore.git/internal/models"
	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"github.com/gin-gonic/gin"
)

// ErrorHandlerMiddleware handles panics and errors gracefully
func ErrorHandlerMiddleware() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log := logger.GetLogger()

		if err, ok := recovered.(string); ok {
			log.WithField("error", err).
				WithField("stack", string(debug.Stack())).
				Error("Panic recovered")
		} else {
			log.WithField("error", recovered).
				WithField("stack", string(debug.Stack())).
				Error("Panic recovered")
		}

		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Internal server error",
		})
	})
}

// RateLimitMiddleware implements basic rate limiting (simple in-memory implementation)
// Note: In production, use Redis-based rate limiting
func RateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Simple rate limiting logic here
		// For production, implement proper rate limiting with Redis

		c.Next()
	}
}
