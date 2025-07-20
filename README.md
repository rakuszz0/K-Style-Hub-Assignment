####  **Singkatkan Bagian Penjelasan Proyek**
> A full-featured e-commerce REST API built with Go (Echo), MySQL, and JWT authentication. Supports product & brand management, with Swagger docs auto-generated.

---

### ✅ **Versi Ringkas dan Revisi (Opsional)**
Kalau kamu ingin versi lebih clean dan profesional, ini contohnya:

---

# Ecommerce API


![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)
![Echo](https://img.shields.io/badge/Echo-v4-blue)
![MySQL](https://img.shields.io/badge/MySQL-8.0+-4479A1?logo=mysql)
![Swagger](https://img.shields.io/badge/Swagger-2.0-85EA2D?logo=swagger)

A complete e-commerce backend API built with Go, Echo framework, and MySQL. Features JWT authentication, product management, and brand operations with auto-generated Swagger documentation.

## 📦 Project Structure

```text
ecommerce/
├── cmd/               # Main application
├── database/          # Database migrations
├── docs/             # Swagger docs
├── dto/              # Data Transfer Objects
│   ├── auth/         # Auth DTOs
│   ├── product/      # Product DTOs
│   ├── brand/        # Brand DTOs
│   └── result/       # API response format
├── handlers/         # Request handlers
├── models/           # DB models
├── pkg/              # Shared packages
│   ├── bcrypt/       # Password hashing
│   ├── jwt/          # JWT auth
│   ├── middleware/   # Custom middleware
│   └── mysql/        # DB connection
├── repo/             # Repository layer
├── routes/           # Route definitions
├── .env.example      # Env configuration
├── go.mod            # Go modules
└── go.sum            # Dependency checksums

## 🚀 Quick Start
### Prerequisites
Go 1.21+

MySQL 8.0+

Git
### Installation
Clone the repo:

git clone https://github.com/rakuszz0/K-Style-Hub-Assignment
Set up environment:
cp .env.example .env
# Edit .env with your credentials
Install dependencies:
go mod download
Run migrations:
go run database/migration.go
Running the Server
go run cmd/main.go
The API will be available at http://localhost:8080

📚 API Documentation
Interactive Swagger docs available at:

text
http://localhost:8080/swagger/index.html
Authentication
All protected routes require JWT in the header:

http
Authorization: Bearer your.jwt.token
Example Endpoints
User Registration

POST /api/v1/products
Authorization: Bearer your.jwt.token
Content-Type: application/json


{
  "name": "John Doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
Product Creation

http
POST /api/v1/products
Authorization: Bearer your.jwt.token
Content-Type: application/json

{
  "name": "Premium Headphones",
  "price": 199.99,
  "brand_id": 1,
  "description": "Noise cancelling wireless headphones"
}
🔧 Configuration
Edit .env file:

ini
DB_HOST=localhost
DB_PORT=3306
DB_USER=dbuser
DB_PASSWORD=dbpassword
DB_NAME=ecommerce
SECRET_KEY=your_jwt_secret_key_here
PORT=8080

🤝 Contributing
Fork the project

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some feature')

Push to the branch (git push origin )

Open a Pull Request

📬 Contact
For support, email: ilahir66@gmail.com
