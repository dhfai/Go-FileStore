package services

import (
	"crypto/tls"
	"fmt"
	"strconv"

	"github.com/dhfai/Go-FileStore.git/internal/config"
	"github.com/dhfai/Go-FileStore.git/pkg/logger"
	"gopkg.in/gomail.v2"
)

// EmailService handles email sending operations
type EmailService struct {
	config *config.EmailConfig
}

// NewEmailService creates a new EmailService
func NewEmailService(cfg *config.EmailConfig) *EmailService {
	return &EmailService{
		config: cfg,
	}
}

// SendOTPEmail sends an OTP email to the user
func (s *EmailService) SendOTPEmail(toEmail, otpCode, purpose string) error {
	log := logger.GetLogger()

	if s.config.SMTPUsername == "" || s.config.SMTPPassword == "" {
		log.Warn("SMTP credentials not configured, skipping email send")
		return fmt.Errorf("SMTP credentials not configured")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", s.config.SMTPUsername)
	m.SetHeader("To", toEmail)

	var subject, body string

	switch purpose {
	case "reset_password":
		subject = "Password Reset OTP - FileStore"
		body = s.generatePasswordResetEmailBody(otpCode)
	case "verify_email":
		subject = "Email Verification OTP - FileStore"
		body = s.generateEmailVerificationBody(otpCode)
	default:
		subject = "OTP Code - FileStore"
		body = s.generateGenericOTPBody(otpCode)
	}

	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	// Parse SMTP port
	port, err := strconv.Atoi(s.config.SMTPPort)
	if err != nil {
		log.WithError(err).Error("Invalid SMTP port")
		return fmt.Errorf("invalid SMTP port: %w", err)
	}

	d := gomail.NewDialer(s.config.SMTPHost, port, s.config.SMTPUsername, s.config.SMTPPassword)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: false}

	if err := d.DialAndSend(m); err != nil {
		log.WithError(err).WithField("email", toEmail).Error("Failed to send email")
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.WithField("email", toEmail).WithField("purpose", purpose).Info("Email sent successfully")
	return nil
}

// generatePasswordResetEmailBody generates the HTML body for password reset email
func (s *EmailService) generatePasswordResetEmailBody(otpCode string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset OTP</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4CAF50; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .otp-code { font-size: 24px; font-weight: bold; color: #4CAF50; text-align: center; padding: 15px; background-color: #e8f5e8; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>You have requested to reset your password. Please use the following OTP code to proceed:</p>
            <div class="otp-code">%s</div>
            <p><strong>Important:</strong></p>
            <ul>
                <li>This OTP is valid for 15 minutes only</li>
                <li>Do not share this code with anyone</li>
                <li>If you didn't request this, please ignore this email</li>
            </ul>
        </div>
        <div class="footer">
            <p>This is an automated email, please do not reply.</p>
            <p>&copy; 2024 FileStore. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, otpCode)
}

// generateEmailVerificationBody generates the HTML body for email verification
func (s *EmailService) generateEmailVerificationBody(otpCode string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification OTP</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #2196F3; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .otp-code { font-size: 24px; font-weight: bold; color: #2196F3; text-align: center; padding: 15px; background-color: #e3f2fd; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Email Verification</h1>
        </div>
        <div class="content">
            <p>Welcome to FileStore!</p>
            <p>Please use the following OTP code to verify your email address:</p>
            <div class="otp-code">%s</div>
            <p><strong>Note:</strong></p>
            <ul>
                <li>This OTP is valid for 15 minutes only</li>
                <li>Do not share this code with anyone</li>
            </ul>
        </div>
        <div class="footer">
            <p>This is an automated email, please do not reply.</p>
            <p>&copy; 2024 FileStore. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, otpCode)
}

// generateGenericOTPBody generates a generic OTP email body
func (s *EmailService) generateGenericOTPBody(otpCode string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>OTP Code</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #FF9800; color: white; padding: 20px; text-align: center; }
        .content { padding: 20px; background-color: #f9f9f9; }
        .otp-code { font-size: 24px; font-weight: bold; color: #FF9800; text-align: center; padding: 15px; background-color: #fff3e0; border-radius: 5px; margin: 20px 0; }
        .footer { text-align: center; padding: 20px; color: #666; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>OTP Code</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Your OTP code is:</p>
            <div class="otp-code">%s</div>
            <p><strong>Note:</strong> This OTP is valid for 15 minutes only.</p>
        </div>
        <div class="footer">
            <p>This is an automated email, please do not reply.</p>
            <p>&copy; 2024 FileStore. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
`, otpCode)
}
