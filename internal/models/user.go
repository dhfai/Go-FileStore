package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents the user table in database
type User struct {
	ID              uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Username        string         `gorm:"type:varchar(50);unique;not null" json:"username" validate:"required,min=3,max=50"`
	Email           string         `gorm:"type:varchar(100);unique;not null" json:"email" validate:"required,email"`
	Password        string         `gorm:"type:varchar(255);not null" json:"-"`
	IsActive        bool           `gorm:"default:true" json:"is_active"`
	EmailVerified   bool           `gorm:"default:false" json:"email_verified"`
	EmailVerifiedAt *time.Time     `gorm:"type:timestamp" json:"email_verified_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	DeletedAt       gorm.DeletedAt `gorm:"index" json:"-"`

	// Relationship
	Profile *Profile `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"profile,omitempty"`
	OTPs    []OTP    `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;" json:"-"`
}

// Profile represents the user profile table in database
type Profile struct {
	ID          uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID      uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	FullName    string    `gorm:"type:varchar(100)" json:"full_name" validate:"max=100"`
	Address     string    `gorm:"type:text" json:"address"`
	PhoneNumber string    `gorm:"type:varchar(20)" json:"phone_number" validate:"max=20"`
	Country     string    `gorm:"type:varchar(50)" json:"country" validate:"max=50"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`

	// Relationship
	User User `gorm:"foreignKey:UserID;references:ID" json:"-"`
}

// OTP represents the OTP table for password reset
type OTP struct {
	ID        uuid.UUID `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index" json:"user_id"`
	Code      string    `gorm:"type:varchar(6);not null" json:"code"`
	Type      string    `gorm:"type:varchar(20);not null" json:"type"` // reset_password, verify_email
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	Used      bool      `gorm:"default:false" json:"used"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationship
	User User `gorm:"foreignKey:UserID;references:ID" json:"-"`
}

// BeforeCreate hook for User
func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return
}

// BeforeCreate hook for Profile
func (p *Profile) BeforeCreate(tx *gorm.DB) (err error) {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	return
}

// BeforeCreate hook for OTP
func (o *OTP) BeforeCreate(tx *gorm.DB) (err error) {
	if o.ID == uuid.Nil {
		o.ID = uuid.New()
	}
	return
}

// TableName for User
func (User) TableName() string {
	return "users"
}

// TableName for Profile
func (Profile) TableName() string {
	return "profiles"
}

// TableName for OTP
func (OTP) TableName() string {
	return "otps"
}
