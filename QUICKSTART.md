# 🚀 File Store API - Quick Start Commands

## Prerequisites
1. **PostgreSQL** - Make sure PostgreSQL is installed and running
2. **Go 1.21+** - Install Go from https://golang.org/download/

## Quick Setup

### 1. Setup Database
```sql
-- Connect to PostgreSQL and create database
CREATE DATABASE filestore_db;
CREATE USER filestore_user WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE filestore_db TO filestore_user;
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit .env file with your database credentials and email settings
```

### 3. Install Dependencies and Build
```bash
# Windows
scripts\setup.bat

# Linux/Mac
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 4. Run the Application
```bash
# Development mode (auto-reload on file changes)
go run cmd/main.go

# Or run the built binary
bin/filestore.exe    # Windows
./bin/filestore      # Linux/Mac
```

## Docker Setup (Alternative)

### Using Docker Compose (Recommended)
```bash
# Start PostgreSQL and API
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

## API Testing

### Method 1: Using HTTP Files (VS Code REST Client)
Open `api-tests.http` in VS Code with REST Client extension

### Method 2: Using Postman
Import `postman-collection.json` into Postman

### Method 3: Using cURL
```bash
# Health check
curl http://localhost:8080/health

# Register user
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePass123!",
    "retype_password": "SecurePass123!"
  }'

# Login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }'
```

## Available Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health` | Health check | No |
| POST | `/api/v1/auth/register` | User registration | No |
| POST | `/api/v1/auth/login` | User login | No |
| POST | `/api/v1/auth/forget-password` | Request password reset | No |
| POST | `/api/v1/auth/reset-password` | Reset password with OTP | No |
| GET | `/api/v1/profile` | Get user profile | Yes |
| PUT | `/api/v1/profile` | Update user profile | Yes |
| DELETE | `/api/v1/profile` | Delete user profile | Yes |
| GET | `/api/v1/user/info` | Get user info | Yes |

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DB_HOST` | Database host | `localhost` |
| `DB_PORT` | Database port | `5432` |
| `DB_USER` | Database username | `postgres` |
| `DB_PASSWORD` | Database password | `password` |
| `DB_NAME` | Database name | `filestore_db` |
| `JWT_SECRET` | JWT signing secret | `your-secret-key` |
| `SERVER_PORT` | Server port | `8080` |
| `SMTP_HOST` | Email SMTP host | `smtp.gmail.com` |
| `SMTP_USERNAME` | Email username | `your-email@gmail.com` |
| `SMTP_PASSWORD` | Email password | `app-password` |

## Troubleshooting

### Database Connection Issues
1. Ensure PostgreSQL is running
2. Check database credentials in `.env`
3. Verify database exists and user has permissions

### Email Issues
1. Use App Password for Gmail (not regular password)
2. Enable 2-factor authentication first
3. Check SMTP settings

### Build Issues
1. Ensure Go 1.21+ is installed
2. Run `go mod tidy` to download dependencies
3. Check for syntax errors in terminal

## Development Tips

### Hot Reload
Use air for hot reload during development:
```bash
# Install air
go install github.com/cosmtrek/air@latest

# Run with hot reload
air
```

### Database Management
Use Adminer (included in docker-compose):
- URL: http://localhost:8081
- Server: postgres
- Username: postgres
- Password: password
- Database: filestore_db

### Logs
The application uses structured logging with different levels:
- Development: Colorized console output
- Production: JSON formatted logs
