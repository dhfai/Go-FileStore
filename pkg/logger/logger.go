package logger

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var log *logrus.Logger

// InitLogger initializes the logger
func InitLogger(environment string) {
	log = logrus.New()

	// Set output to stdout
	log.SetOutput(os.Stdout)

	// Set log level based on environment
	if strings.ToLower(environment) == "development" {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}

	// Set formatter based on environment
	if strings.ToLower(environment) == "development" {
		// Use text formatter for development (prettier for console)
		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02 15:04:05",
			ForceColors:     true,
			PadLevelText:    true,
		})
	} else {
		// Use JSON formatter for production
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z",
			PrettyPrint:     false,
		})
	}

	log.Info("Logger initialized successfully")
}

// GetLogger returns the logger instance
func GetLogger() *logrus.Logger {
	if log == nil {
		InitLogger("development")
	}
	return log
}

// WithField creates an entry with a field
func WithField(key string, value interface{}) *logrus.Entry {
	return GetLogger().WithField(key, value)
}

// WithFields creates an entry with multiple fields
func WithFields(fields logrus.Fields) *logrus.Entry {
	return GetLogger().WithFields(fields)
}

// WithError creates an entry with an error field
func WithError(err error) *logrus.Entry {
	return GetLogger().WithError(err)
}

// Debug logs a debug message
func Debug(args ...interface{}) {
	GetLogger().Debug(args...)
}

// Info logs an info message
func Info(args ...interface{}) {
	GetLogger().Info(args...)
}

// Warn logs a warning message
func Warn(args ...interface{}) {
	GetLogger().Warn(args...)
}

// Error logs an error message
func Error(args ...interface{}) {
	GetLogger().Error(args...)
}

// Fatal logs a fatal message and exits
func Fatal(args ...interface{}) {
	GetLogger().Fatal(args...)
}

// Debugf logs a debug message with formatting
func Debugf(format string, args ...interface{}) {
	GetLogger().Debugf(format, args...)
}

// Infof logs an info message with formatting
func Infof(format string, args ...interface{}) {
	GetLogger().Infof(format, args...)
}

// Warnf logs a warning message with formatting
func Warnf(format string, args ...interface{}) {
	GetLogger().Warnf(format, args...)
}

// Errorf logs an error message with formatting
func Errorf(format string, args ...interface{}) {
	GetLogger().Errorf(format, args...)
}

// Fatalf logs a fatal message with formatting and exits
func Fatalf(format string, args ...interface{}) {
	GetLogger().Fatalf(format, args...)
}
