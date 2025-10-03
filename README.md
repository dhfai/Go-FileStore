# File Store API

A robust Go backend API with authentication system featuring login, registration, profile management, and password reset functionality.

## Features

### 🔐 Authentication System
- **Login**: Email and password authentication
- **Register**: Username, email, password with validation
- **Profile Management**: Full name, address, phone number, country
- **Forget Password**: OTP-based password reset via email

### 🏗️ Architecture
- **Clean Architecture**: Atomic folder structure for easy management
- **Database**: PostgreSQL with GORM
- **Logging**: Beautiful and structured logging with Logrus
- **Security**: JWT tokens, password hashing, CORS, security headers
- **Validation**: Comprehensive input validation
- **Email**: HTML email templates for OTP

## Project Structure

```
file-store/
├── cmd/
│   └── main.go                 # Application entry point
├── internal/
│   ├── config/                 # Configuration management
│   │   ├── config.go
│   │   └── database.go
│   ├── controllers/            # HTTP handlers
│   │   ├── auth_controller.go
│   │   └── profile_controller.go
│   ├── middleware/             # HTTP middleware
│   │   ├── auth.go
│   │   ├── cors.go
│   │   ├── error.go
│   │   └── logger.go
│   ├── models/                 # Data models and DTOs
│   │   ├── dto.go
│   │   └── user.go
│   ├── routes/                 # Route definitions
│   │   └── routes.go
│   ├── services/               # Business logic
│   │   ├── auth_service.go
│   │   └── email_service.go
│   └── utils/                  # Utility functions
│       └── validation.go
├── pkg/
│   └── logger/                 # Logging utilities
│       └── logger.go
├── migrations/                 # Database migrations
├── .env.example               # Environment variables template
├── go.mod                     # Go module definition
└── README.md                  # This file
```

## API Endpoints

### Authentication Endpoints

#### Register (Sends Verification Email)
```http
POST /api/v1/auth/register
Content-Type: application/json

{
    "username": "johndoe",
    "email": "john@example.com",
    "password": "SecurePass123!",
    "retype_password": "SecurePass123!"
}
```

#### Verify Email
```http
POST /api/v1/auth/verify-email
Content-Type: application/json

{
    "email": "john@example.com",
    "code": "123456"
}
```

#### Resend Verification Email
```http
POST /api/v1/auth/resend-verification
Content-Type: application/json

{
    "email": "john@example.com"
}
```

#### Login (Requires Verified Email)
```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "SecurePass123!"
}
```

#### Forget Password
```http
POST /api/v1/auth/forget-password
Content-Type: application/json

{
    "email": "john@example.com"
}
```

#### Reset Password
```http
POST /api/v1/auth/reset-password
Content-Type: application/json

{
    "email": "john@example.com",
    "otp_code": "123456",
    "new_password": "NewSecurePass123!"
}
```

#### Logout (Requires Authentication)
```http
POST /api/v1/auth/logout
Authorization: Bearer <jwt_token>
```

#### Request Delete Account (Requires Authentication)
```http
POST /api/v1/auth/request-delete-account
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "password": "your_current_password"
}
```

#### Delete Account (Requires Authentication)
```http
POST /api/v1/auth/delete-account
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "code": "123456"
}
```

**⚠️ Important:** This is a **HARD DELETE** operation. All user data including:
- User account
- Profile information
- All OTP records
- Token blacklist entries

Will be **permanently removed** from the database and **cannot be recovered**.

### Profile Endpoints (Requires Authentication)

#### Get Profile
```http
GET /api/v1/profile
Authorization: Bearer <jwt_token>
```

#### Update Profile
```http
PUT /api/v1/profile
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
    "full_name": "John Doe",
    "address": "123 Main St, City",
    "phone_number": "+1234567890",
    "country": "USA"
}
```

#### Get User Info
```http
GET /api/v1/user/info
Authorization: Bearer <jwt_token>
```

## Setup Instructions

### Prerequisites
- Go 1.21 or higher
- PostgreSQL 12 or higher

### 1. Clone the Repository
```bash
git clone <repository-url>
cd file-store
```

### 2. Environment Configuration
```bash
cp .env.example .env
```

Edit `.env` file with your configuration:
```env
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_password
DB_NAME=filestore_db
DB_SSLMODE=disable

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-here

# Server Configuration
SERVER_PORT=8080
SERVER_HOST=localhost

# Email Configuration (for OTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password

# Environment
ENV=development
```

### 3. Database Setup
Create PostgreSQL database:
```sql
CREATE DATABASE filestore_db;
```

### 4. Install Dependencies
```bash
go mod tidy
```

### 5. Run the Application
```bash
# Development mode
go run cmd/main.go

# Or build and run
go build -o bin/filestore cmd/main.go
./bin/filestore
```

## Email Configuration

For Gmail SMTP:
1. Enable 2-factor authentication
2. Generate an App Password
3. Use the App Password in `SMTP_PASSWORD`

## Security Features

- **Password Hashing**: bcrypt with salt
- **JWT Tokens**: 7-day expiration
- **Input Validation**: Comprehensive validation rules
- **SQL Injection Prevention**: GORM ORM protection
- **CORS**: Configurable cross-origin requests
- **Security Headers**: XSS protection, clickjacking prevention
- **Rate Limiting**: Basic implementation (extend for production)

## Logging

The application uses structured logging with different levels:
- **Development**: Colorized console output
- **Production**: JSON formatted logs

Log levels:
- `DEBUG`: Detailed debugging information
- `INFO`: General information
- `WARN`: Warning messages
- `ERROR`: Error messages
- `FATAL`: Fatal errors that cause application exit

## Database Schema

### Users Table
- `id` (UUID, Primary Key)
- `username` (VARCHAR, Unique)
- `email` (VARCHAR, Unique)
- `password` (VARCHAR, Hashed)
- `is_active` (BOOLEAN)
- `created_at`, `updated_at`, `deleted_at`

### Profiles Table
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key)
- `full_name` (VARCHAR)
- `address` (TEXT)
- `phone_number` (VARCHAR)
- `country` (VARCHAR)
- `created_at`, `updated_at`

### OTPs Table
- `id` (UUID, Primary Key)
- `user_id` (UUID, Foreign Key)
- `code` (VARCHAR, 6 digits)
- `type` (VARCHAR, reset_password/verify_email/delete_account)
- `expires_at` (TIMESTAMP)
- `used` (BOOLEAN)
- `created_at`, `updated_at`

### TokenBlacklist Table
- `id` (UUID, Primary Key)
- `token` (TEXT, JWT token)
- `expires_at` (TIMESTAMP)
- `created_at`

## 🧹 Cleanup & Maintenance

### Automatic Cleanup
The system includes automatic cleanup service that runs every 24 hours:
- **Expired Tokens**: Removes expired tokens from blacklist table
- **Used/Expired OTPs**: Removes used or expired OTP codes
- **Initial Cleanup**: Runs on application startup

### Hard Delete Policy
- **Account Deletion**: Permanently removes all user data (hard delete)
- **Cascade Deletion**: Automatically removes related profile and OTP data
- **Token Blacklist**: User's current token is immediately blacklisted
- **Email Availability**: Deleted email addresses become available for re-registration

## 📮 API Testing

### Postman Collection
Complete Postman collection tersedia di folder `postman/`:
- `postman-collection.json` - Complete API collection dengan semua endpoints
- `filestore-environment.json` - Environment variables template
- `README.md` - Detailed setup dan usage guide

**Features:**
- ✅ Auto token management (login saves token, logout clears token)
- ✅ Environment variables untuk easy testing
- ✅ Complete request examples untuk semua endpoints
- ✅ Test scripts untuk workflow automation
- ✅ Pre-configured untuk development dan production testing

**Quick Setup:**
1. Import kedua files ke Postman
2. Pilih "File Store API Environment"
3. Run Register → Verify Email → Login
4. Token otomatis tersimpan, siap untuk testing protected endpoints

### VS Code REST Client
Test files tersedia di folder `tests/`:
- `api-tests.http` - Basic API testing
- `email_verification_api.http` - Email verification flow
- `logout_and_delete_api.http` - Logout dan delete account testing
- `delete_account_hard_delete_test.http` - Hard delete verification testing

## Error Handling

All API responses follow a consistent format:
```json
{
    "success": true/false,
    "message": "Description of the result",
    "data": {}, // Present on successful responses
    "error": {} // Present on error responses
}
```
