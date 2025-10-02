package controllers

import (
	"net/http"
	"time"

	"github.com/dhfai/Go-FileStore.git/internal/models"
	"github.com/dhfai/Go-FileStore.git/internal/services"
	"github.com/dhfai/Go-FileStore.git/internal/utils"
	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// AuthController handles authentication related requests
type AuthController struct {
	db           *gorm.DB
	authService  *services.AuthService
	emailService *services.EmailService
}

// NewAuthController creates a new AuthController
func NewAuthController(db *gorm.DB, authService *services.AuthService, emailService *services.EmailService) *AuthController {
	return &AuthController{
		db:           db,
		authService:  authService,
		emailService: emailService,
	}
}

// Register handles user registration
func (ac *AuthController) Register(c *gin.Context) {
	log := logger.GetLogger()

	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind registration request")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid request format",
			Error:   err.Error(),
		})
		return
	}

	// Validate request
	if validationErrors := utils.ValidateStruct(req); validationErrors != nil {
		log.WithField("validation_errors", validationErrors).Warn("Registration validation failed")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   validationErrors,
		})
		return
	}

	// Normalize email and username
	req.Email = utils.NormalizeEmail(req.Email)
	req.Username = utils.NormalizeUsername(req.Username)

	// Check if user already exists
	var existingUser models.User
	if err := ac.db.Where("email = ? OR username = ?", req.Email, req.Username).First(&existingUser).Error; err == nil {
		log.WithField("email", req.Email).WithField("username", req.Username).Warn("User already exists")
		c.JSON(http.StatusConflict, models.APIResponse{
			Success: false,
			Message: "User with this email or username already exists",
		})
		return
	}

	// Hash password
	hashedPassword, err := ac.authService.HashPassword(req.Password)
	if err != nil {
		log.WithError(err).Error("Failed to hash password")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process registration",
		})
		return
	}

	// Create user
	user := models.User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
		IsActive: true,
	}

	if err := ac.db.Create(&user).Error; err != nil {
		log.WithError(err).Error("Failed to create user")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to create user",
		})
		return
	}

	// Create empty profile
	profile := models.Profile{
		UserID: user.ID,
	}
	if err := ac.db.Create(&profile).Error; err != nil {
		log.WithError(err).Error("Failed to create user profile")
		// Continue execution as profile creation is not critical for registration
	}

	// Generate email verification OTP
	otpCode, err := ac.authService.GenerateOTP()
	if err != nil {
		log.WithError(err).Error("Failed to generate verification OTP")
		// Continue with registration even if OTP generation fails
	} else {
		// Save OTP to database
		otp := models.OTP{
			UserID:    user.ID,
			Code:      otpCode,
			Type:      "verify_email",
			ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minutes expiry
			Used:      false,
		}

		if err := ac.db.Create(&otp).Error; err != nil {
			log.WithError(err).Error("Failed to save verification OTP")
			// Continue execution as OTP saving is not critical for registration
		} else {
			// Send verification email
			if err := ac.emailService.SendOTPEmail(user.Email, otpCode, "verify_email"); err != nil {
				log.WithError(err).Error("Failed to send verification email")
				// Continue execution as email sending is not critical for registration
			} else {
				log.WithField("user_id", user.ID).Info("Verification email sent")
			}
		}
	}

	log.WithField("user_id", user.ID).WithField("email", user.Email).Info("User registered successfully")

	c.JSON(http.StatusCreated, models.APIResponse{
		Success: true,
		Message: "User registered successfully. Please check your email for verification code.",
		Data:    user.ToUserResponse(),
	})
}

// Login handles user login
func (ac *AuthController) Login(c *gin.Context) {
	log := logger.GetLogger()

	var req models.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind login request")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid request format",
			Error:   err.Error(),
		})
		return
	}

	// Validate request
	if validationErrors := utils.ValidateStruct(req); validationErrors != nil {
		log.WithField("validation_errors", validationErrors).Warn("Login validation failed")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   validationErrors,
		})
		return
	}

	// Normalize email
	req.Email = utils.NormalizeEmail(req.Email)

	// Find user
	var user models.User
	if err := ac.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		log.WithField("email", req.Email).Warn("User not found")
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Check if user is active
	if !user.IsActive {
		log.WithField("user_id", user.ID).Warn("Inactive user attempted login")
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Message: "Account is inactive",
		})
		return
	}

	// Check if email is verified
	if !user.EmailVerified {
		log.WithField("user_id", user.ID).Warn("Unverified email attempted login")
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Message: "Please verify your email before logging in. Check your inbox for verification code.",
		})
		return
	}

	// Verify password
	if !ac.authService.VerifyPassword(user.Password, req.Password) {
		log.WithField("user_id", user.ID).Warn("Invalid password attempt")
		c.JSON(http.StatusUnauthorized, models.APIResponse{
			Success: false,
			Message: "Invalid email or password",
		})
		return
	}

	// Generate token
	token, err := ac.authService.GenerateToken(user.ID.String(), user.Email)
	if err != nil {
		log.WithError(err).Error("Failed to generate token")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to generate authentication token",
		})
		return
	}

	// Load user profile
	var profile models.Profile
	if err := ac.db.Where("user_id = ?", user.ID).First(&profile).Error; err == nil {
		user.Profile = &profile
	}

	log.WithField("user_id", user.ID).Info("User logged in successfully")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Login successful",
		Data: models.LoginResponse{
			Token: token,
			User:  user.ToUserResponse(),
		},
	})
}

// ForgetPassword handles password reset request
func (ac *AuthController) ForgetPassword(c *gin.Context) {
	log := logger.GetLogger()

	var req models.ForgetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind forget password request")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid request format",
			Error:   err.Error(),
		})
		return
	}

	// Validate request
	if validationErrors := utils.ValidateStruct(req); validationErrors != nil {
		log.WithField("validation_errors", validationErrors).Warn("Forget password validation failed")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   validationErrors,
		})
		return
	}

	// Normalize email
	req.Email = utils.NormalizeEmail(req.Email)

	// Find user
	var user models.User
	if err := ac.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Don't reveal if email exists or not for security
		log.WithField("email", req.Email).Warn("Forget password request for non-existent email")
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Message: "If your email is registered, you will receive a password reset code",
		})
		return
	}

	// Generate OTP
	otpCode, err := ac.authService.GenerateOTP()
	if err != nil {
		log.WithError(err).Error("Failed to generate OTP")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process request",
		})
		return
	}

	// Save OTP to database
	otp := models.OTP{
		UserID:    user.ID,
		Code:      otpCode,
		Type:      "reset_password",
		ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minutes expiry
		Used:      false,
	}

	if err := ac.db.Create(&otp).Error; err != nil {
		log.WithError(err).Error("Failed to save OTP")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process request",
		})
		return
	}

	// Send OTP email
	if err := ac.emailService.SendOTPEmail(user.Email, otpCode, "reset_password"); err != nil {
		log.WithError(err).Error("Failed to send OTP email")
		// Continue execution as email sending is not critical
	}

	log.WithField("user_id", user.ID).Info("Password reset OTP generated")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Password reset code sent to your email",
	})
}

// ResetPassword handles password reset with OTP
func (ac *AuthController) ResetPassword(c *gin.Context) {
	log := logger.GetLogger()

	var req models.ResetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind reset password request")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid request format",
			Error:   err.Error(),
		})
		return
	}

	// Validate request
	if validationErrors := utils.ValidateStruct(req); validationErrors != nil {
		log.WithField("validation_errors", validationErrors).Warn("Reset password validation failed")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   validationErrors,
		})
		return
	}

	// Normalize email
	req.Email = utils.NormalizeEmail(req.Email)

	// Find user
	var user models.User
	if err := ac.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		log.WithField("email", req.Email).Warn("Reset password request for non-existent email")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid email or OTP code",
		})
		return
	}

	// Find valid OTP
	var otp models.OTP
	if err := ac.db.Where("user_id = ? AND code = ? AND type = ? AND used = ? AND expires_at > ?",
		user.ID, req.OTPCode, "reset_password", false, time.Now()).First(&otp).Error; err != nil {
		log.WithField("user_id", user.ID).WithField("otp_code", req.OTPCode).Warn("Invalid or expired OTP")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid or expired OTP code",
		})
		return
	}

	// Hash new password
	hashedPassword, err := ac.authService.HashPassword(req.NewPassword)
	if err != nil {
		log.WithError(err).Error("Failed to hash new password")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process request",
		})
		return
	}

	// Update password and mark OTP as used
	tx := ac.db.Begin()

	// Update user password
	if err := tx.Model(&user).Update("password", hashedPassword).Error; err != nil {
		tx.Rollback()
		log.WithError(err).Error("Failed to update password")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to update password",
		})
		return
	}

	// Mark OTP as used
	if err := tx.Model(&otp).Update("used", true).Error; err != nil {
		tx.Rollback()
		log.WithError(err).Error("Failed to mark OTP as used")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process request",
		})
		return
	}

	tx.Commit()

	log.WithField("user_id", user.ID).Info("Password reset successfully")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Password reset successfully",
	})
}

// VerifyEmail handles email verification with OTP
func (ac *AuthController) VerifyEmail(c *gin.Context) {
	log := logger.GetLogger()

	var req models.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind verify email request")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid request format",
			Error:   err.Error(),
		})
		return
	}

	// Validate request
	if validationErrors := utils.ValidateStruct(req); validationErrors != nil {
		log.WithField("validation_errors", validationErrors).Warn("Email verification validation failed")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   validationErrors,
		})
		return
	}

	// Normalize email
	req.Email = utils.NormalizeEmail(req.Email)

	// Find user
	var user models.User
	if err := ac.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		log.WithField("email", req.Email).Warn("Email verification request for non-existent email")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid email or verification code",
		})
		return
	}

	// Check if email is already verified
	if user.EmailVerified {
		log.WithField("user_id", user.ID).Warn("Email already verified")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Email is already verified",
		})
		return
	}

	// Find valid OTP
	var otp models.OTP
	if err := ac.db.Where("user_id = ? AND code = ? AND type = ? AND used = ? AND expires_at > ?",
		user.ID, req.OTPCode, "verify_email", false, time.Now()).First(&otp).Error; err != nil {
		log.WithField("user_id", user.ID).WithField("otp_code", req.OTPCode).Warn("Invalid or expired verification OTP")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid or expired verification code",
		})
		return
	}

	// Update user email verification status and mark OTP as used
	tx := ac.db.Begin()

	now := time.Now()
	// Update user email verification
	if err := tx.Model(&user).Updates(map[string]interface{}{
		"email_verified":    true,
		"email_verified_at": &now,
	}).Error; err != nil {
		tx.Rollback()
		log.WithError(err).Error("Failed to update email verification status")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to verify email",
		})
		return
	}

	// Mark OTP as used
	if err := tx.Model(&otp).Update("used", true).Error; err != nil {
		tx.Rollback()
		log.WithError(err).Error("Failed to mark OTP as used")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process verification",
		})
		return
	}

	tx.Commit()

	log.WithField("user_id", user.ID).Info("Email verified successfully")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Email verified successfully. You can now login.",
	})
}

// ResendVerification resends email verification OTP
func (ac *AuthController) ResendVerification(c *gin.Context) {
	log := logger.GetLogger()

	var req models.ResendVerificationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.WithError(err).Error("Failed to bind resend verification request")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Invalid request format",
			Error:   err.Error(),
		})
		return
	}

	// Validate request
	if validationErrors := utils.ValidateStruct(req); validationErrors != nil {
		log.WithField("validation_errors", validationErrors).Warn("Resend verification validation failed")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Validation failed",
			Error:   validationErrors,
		})
		return
	}

	// Normalize email
	req.Email = utils.NormalizeEmail(req.Email)

	// Find user
	var user models.User
	if err := ac.db.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Don't reveal if email exists or not for security
		log.WithField("email", req.Email).Warn("Resend verification request for non-existent email")
		c.JSON(http.StatusOK, models.APIResponse{
			Success: true,
			Message: "If your email is registered and not verified, you will receive a verification code",
		})
		return
	}

	// Check if email is already verified
	if user.EmailVerified {
		log.WithField("user_id", user.ID).Warn("Resend verification for already verified email")
		c.JSON(http.StatusBadRequest, models.APIResponse{
			Success: false,
			Message: "Email is already verified",
		})
		return
	}

	// Generate OTP
	otpCode, err := ac.authService.GenerateOTP()
	if err != nil {
		log.WithError(err).Error("Failed to generate verification OTP")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process request",
		})
		return
	}

	// Save OTP to database
	otp := models.OTP{
		UserID:    user.ID,
		Code:      otpCode,
		Type:      "verify_email",
		ExpiresAt: time.Now().Add(15 * time.Minute), // 15 minutes expiry
		Used:      false,
	}

	if err := ac.db.Create(&otp).Error; err != nil {
		log.WithError(err).Error("Failed to save verification OTP")
		c.JSON(http.StatusInternalServerError, models.APIResponse{
			Success: false,
			Message: "Failed to process request",
		})
		return
	}

	// Send verification email
	if err := ac.emailService.SendOTPEmail(user.Email, otpCode, "verify_email"); err != nil {
		log.WithError(err).Error("Failed to send verification email")
		// Continue execution as email sending is not critical
	}

	log.WithField("user_id", user.ID).Info("Email verification OTP resent")

	c.JSON(http.StatusOK, models.APIResponse{
		Success: true,
		Message: "Verification code sent to your email",
	})
}
