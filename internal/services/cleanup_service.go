package services

import (
	"time"

	"github.com/dhfai/Go-FileStore.git/internal/models"
	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"gorm.io/gorm"
)

// CleanupService handles cleanup operations
type CleanupService struct {
	db *gorm.DB
}

// NewCleanupService creates a new CleanupService
func NewCleanupService(db *gorm.DB) *CleanupService {
	return &CleanupService{
		db: db,
	}
}

// CleanupExpiredTokens removes expired tokens from blacklist
func (s *CleanupService) CleanupExpiredTokens() error {
	log := logger.GetLogger()

	result := s.db.Where("expires_at < ?", time.Now()).Delete(&models.TokenBlacklist{})
	if result.Error != nil {
		log.WithError(result.Error).Error("Failed to cleanup expired tokens")
		return result.Error
	}

	if result.RowsAffected > 0 {
		log.WithField("deleted_count", result.RowsAffected).Info("Cleaned up expired tokens")
	}

	return nil
}

// CleanupExpiredOTPs removes expired and used OTPs
func (s *CleanupService) CleanupExpiredOTPs() error {
	log := logger.GetLogger()

	// Delete expired or used OTPs
	result := s.db.Where("expires_at < ? OR used = ?", time.Now(), true).Delete(&models.OTP{})
	if result.Error != nil {
		log.WithError(result.Error).Error("Failed to cleanup expired OTPs")
		return result.Error
	}

	if result.RowsAffected > 0 {
		log.WithField("deleted_count", result.RowsAffected).Info("Cleaned up expired/used OTPs")
	}

	return nil
}

// RunCleanup runs all cleanup operations
func (s *CleanupService) RunCleanup() {
	log := logger.GetLogger()

	log.Info("Starting cleanup operations...")

	if err := s.CleanupExpiredTokens(); err != nil {
		log.WithError(err).Error("Token cleanup failed")
	}

	if err := s.CleanupExpiredOTPs(); err != nil {
		log.WithError(err).Error("OTP cleanup failed")
	}

	log.Info("Cleanup operations completed")
}
