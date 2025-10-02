package middleware

import (
	"time"

	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

// LoggerMiddleware logs HTTP requests with beautiful formatting
func LoggerMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		log := logger.GetLogger()

		// Determine log level based on status code
		var logLevel logrus.Level
		switch {
		case param.StatusCode >= 500:
			logLevel = logrus.ErrorLevel
		case param.StatusCode >= 400:
			logLevel = logrus.WarnLevel
		default:
			logLevel = logrus.InfoLevel
		}

		// Create log entry with structured fields
		entry := log.WithFields(logrus.Fields{
			"method":     param.Method,
			"path":       param.Path,
			"status":     param.StatusCode,
			"latency":    param.Latency,
			"client_ip":  param.ClientIP,
			"user_agent": param.Request.UserAgent(),
			"request_id": param.Request.Header.Get("X-Request-ID"),
		})

		// Log the request
		message := "HTTP Request"
		switch logLevel {
		case logrus.ErrorLevel:
			entry.Error(message)
		case logrus.WarnLevel:
			entry.Warn(message)
		default:
			entry.Info(message)
		}

		// Return empty string since we're using logrus for logging
		return ""
	})
}

// RequestIDMiddleware adds a unique request ID to each request
func RequestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			// Generate a simple request ID (in production, use a proper UUID)
			requestID = generateRequestID()
		}

		c.Header("X-Request-ID", requestID)
		c.Set("request_id", requestID)
		c.Next()
	}
}

// generateRequestID generates a simple request ID
func generateRequestID() string {
	return time.Now().Format("20060102-150405") + "-" + generateRandomString(6)
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
