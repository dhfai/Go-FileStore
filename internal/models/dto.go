package models

// Request and Response DTOs

// RegisterRequest represents the registration request payload
type RegisterRequest struct {
	Username       string `json:"username" validate:"required,min=3,max=50"`
	Email          string `json:"email" validate:"required,email"`
	Password       string `json:"password" validate:"required,min=8"`
	RetypePassword string `json:"retype_password" validate:"required,eqfield=Password"`
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// ForgetPasswordRequest represents the forget password request payload
type ForgetPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

// ResetPasswordRequest represents the reset password request payload
type ResetPasswordRequest struct {
	Email       string `json:"email" validate:"required,email"`
	OTPCode     string `json:"otp_code" validate:"required,len=6"`
	NewPassword string `json:"new_password" validate:"required,min=8"`
}

// UpdateProfileRequest represents the update profile request payload
type UpdateProfileRequest struct {
	FullName    string `json:"full_name" validate:"max=100"`
	Address     string `json:"address"`
	PhoneNumber string `json:"phone_number" validate:"max=20"`
	Country     string `json:"country" validate:"max=50"`
}

// LoginResponse represents the login response
type LoginResponse struct {
	Token string        `json:"token"`
	User  *UserResponse `json:"user"`
}

// UserResponse represents the user response (without sensitive data)
type UserResponse struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	IsActive bool     `json:"is_active"`
	Profile  *Profile `json:"profile,omitempty"`
}

// APIResponse represents a standard API response
type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
	Error   interface{} `json:"error,omitempty"`
}

// ValidationError represents validation error details
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ToUserResponse converts User model to UserResponse
func (u *User) ToUserResponse() *UserResponse {
	return &UserResponse{
		ID:       u.ID.String(),
		Username: u.Username,
		Email:    u.Email,
		IsActive: u.IsActive,
		Profile:  u.Profile,
	}
}
