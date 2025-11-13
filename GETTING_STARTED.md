# Getting Started with WuzAPI - Go Beginner's Guide

This guide explains the Go libraries used in this project and how to start the server.

## 📚 Understanding the Go Libraries

Here's what each library does in this project:

### Core Web Framework & Routing
- **`github.com/gorilla/mux`** - HTTP router and URL matcher. Handles all API routes (like `/session/connect`, `/chat/send/text`, etc.)
- **`github.com/justinas/alice`** - Middleware chaining. Helps organize authentication and logging middleware

### Database
- **`github.com/lib/pq`** - PostgreSQL driver for Go. Connects to PostgreSQL database
- **`github.com/jmoiron/sqlx`** - Extensions to Go's database/sql. Makes database queries easier
- **`modernc.org/sqlite`** - SQLite database driver. Used as an alternative to PostgreSQL

### WhatsApp Integration
- **`go.mau.fi/whatsmeow`** - The main WhatsApp library. Connects to WhatsApp WebSocket servers to send/receive messages
- **`go.mau.fi/whatsmeow/store/sqlstore`** - Stores WhatsApp session data in the database

### Logging
- **`github.com/rs/zerolog`** - Fast, structured logging library. Handles all console and JSON logging

### HTTP Client
- **`github.com/go-resty/resty/v2`** - HTTP client library. Makes HTTP requests to external APIs/webhooks

### Caching
- **`github.com/patrickmn/go-cache`** - In-memory key-value cache. Stores temporary data like user info

### AWS S3 Integration
- **`github.com/aws/aws-sdk-go-v2`** - AWS SDK for Go. Handles S3 file uploads/downloads
- **`github.com/aws/aws-sdk-go-v2/service/s3`** - S3-specific service client
- **`github.com/aws/aws-sdk-go-v2/credentials`** - AWS credential management

### Message Queue
- **`github.com/rabbitmq/amqp091-go`** - RabbitMQ client. Publishes WhatsApp events to message queues

### Image Processing
- **`golang.org/x/image`** - Image processing utilities
- **`github.com/nfnt/resize`** - Image resizing library
- **`github.com/PuerkitoBio/goquery`** - HTML parsing (for web scraping)

### QR Code Generation
- **`github.com/skip2/go-qrcode`** - Generates QR codes for WhatsApp login
- **`github.com/mdp/qrterminal/v3`** - Displays QR codes in terminal

### Utilities
- **`github.com/joho/godotenv`** - Loads `.env` files for configuration
- **`github.com/vincent-petithory/dataurl`** - Handles data URLs (base64 encoded images)
- **`google.golang.org/protobuf`** - Protocol Buffers (used by whatsmeow internally)
- **`golang.org/x/sync`** - Synchronization primitives (for concurrent operations)
- **`golang.org/x/net`** - Network utilities
- **`golang.org/x/crypto`** - Cryptographic functions
- **`golang.org/x/text`** - Text processing utilities

## 🚀 How to Start the Server

### Prerequisites

1. **Install Go** (if not already installed):
   ```bash
   # Check if Go is installed
   go version
   
   # If not installed, download from https://go.dev/dl/
   ```

2. **Install dependencies**:
   ```bash
   cd /home/rj/Docker/wuzapi
   go mod download
   ```

### Method 1: Run Natively (Direct Go Execution)

1. **Create a `.env` file** (optional but recommended):
   ```bash
   # Copy from sample if available, or create new
   cat > .env << EOF
   WUZAPI_ADMIN_TOKEN=your_secure_admin_token_here
   WUZAPI_GLOBAL_ENCRYPTION_KEY=your_32_byte_key_here
   WUZAPI_GLOBAL_HMAC_KEY=your_hmac_key_here
   TZ=America/New_York
   SESSION_DEVICE_NAME=WuzAPI
   EOF
   ```

2. **Build the application**:
   ```bash
   go build .
   ```
   This creates an executable file named `wuzapi` (or `wuzapi.exe` on Windows)

3. **Run the server**:
   ```bash
   # Basic run (defaults: port 8080, address 0.0.0.0)
   ./wuzapi
   
   # With custom port
   ./wuzapi -port=3000
   
   # With colored console logs
   ./wuzapi -logtype=console -color=true
   
   # With JSON logs (for production)
   ./wuzapi -logtype=json
   
   # With SSL/HTTPS
   ./wuzapi -sslcertificate=/path/to/cert.pem -sslprivatekey=/path/to/key.pem
   ```

4. **Or run directly with `go run`** (without building first):
   ```bash
   go run main.go
   ```

### Method 2: Run with Docker Compose (Recommended)

1. **Create a `.env` file** in the project root:
   ```bash
   cat > .env << EOF
   WUZAPI_ADMIN_TOKEN=your_secure_admin_token_here
   WUZAPI_GLOBAL_ENCRYPTION_KEY=your_32_byte_key_here
   WUZAPI_GLOBAL_HMAC_KEY=your_hmac_key_here
   DB_USER=wuzapi
   DB_PASSWORD=wuzapi
   DB_NAME=wuzapi
   DB_PORT=5432
   TZ=America/New_York
   WUZAPI_PORT=8080
   EOF
   ```

2. **Start with Docker Compose**:
   ```bash
   docker-compose up -d
   ```
   This will:
   - Build the Go application
   - Start PostgreSQL database
   - Start the WuzAPI server
   - Connect them together

3. **View logs**:
   ```bash
   docker-compose logs -f wuzapi-server
   ```

4. **Stop the server**:
   ```bash
   docker-compose down
   ```

### Command Line Options

The server accepts these flags:

| Flag | Description | Default |
|------|-------------|---------|
| `-address` | IP address to bind to | `0.0.0.0` |
| `-port` | Port number | `8080` |
| `-admintoken` | Admin authentication token | (from `.env` or auto-generated) |
| `-logtype` | Log format: `console` or `json` | `console` |
| `-color` | Enable colored console output | `false` |
| `-osname` | Device name shown in WhatsApp | `Mac OS 10` |
| `-skipmedia` | Skip downloading media from messages | `false` |
| `-wadebug` | WhatsApp debug level: `INFO` or `DEBUG` | (disabled) |
| `-sslcertificate` | Path to SSL certificate file | (disabled) |
| `-sslprivatekey` | Path to SSL private key file | (disabled) |
| `-version` | Show version and exit | - |

### Environment Variables

You can also configure via `.env` file or environment variables:

- `WUZAPI_ADMIN_TOKEN` - Admin token for admin endpoints
- `WUZAPI_GLOBAL_ENCRYPTION_KEY` - 32-byte encryption key
- `WUZAPI_GLOBAL_HMAC_KEY` - HMAC key for webhook signing
- `WUZAPI_GLOBAL_WEBHOOK` - Global webhook URL
- `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_HOST`, `DB_PORT` - Database config
- `TZ` - Timezone (e.g., `America/New_York`)
- `SESSION_DEVICE_NAME` - Device name in WhatsApp
- `RABBITMQ_URL` - RabbitMQ connection URL (optional)
- `RABBITMQ_QUEUE` - RabbitMQ queue name (optional)

### Verify Server is Running

1. **Check health endpoint**:
   ```bash
   curl http://localhost:8080/health
   ```

2. **Access the dashboard**:
   Open browser: `http://localhost:8080/dashboard`

3. **View API documentation**:
   Open browser: `http://localhost:8080/api`

4. **Access login page**:
   Open browser: `http://localhost:8080/login`

## 🔍 Understanding the Code Structure

- **`main.go`** - Entry point, server initialization, HTTP server setup
- **`routes.go`** - Defines all API routes and middleware
- **`handlers.go`** - Contains all HTTP handler functions (the actual API logic)
- **`db.go`** - Database connection and initialization
- **`clients.go`** - WhatsApp client management
- **`rabbitmq.go`** - RabbitMQ integration
- **`s3manager.go`** - AWS S3 file management
- **`helpers.go`** - Utility functions
- **`constants.go`** - Constants used throughout the app
- **`migrations.go`** - Database schema migrations

## 🐛 Troubleshooting

1. **Port already in use**:
   ```bash
   # Change port
   ./wuzapi -port=3000
   ```

2. **Database connection error**:
   - Check if PostgreSQL is running (if using PostgreSQL)
   - Verify database credentials in `.env`
   - For Docker: ensure `DB_HOST=db` (not `localhost`)

3. **Permission denied**:
   ```bash
   chmod +x wuzapi
   ```

4. **Dependencies not found**:
   ```bash
   go mod tidy
   go mod download
   ```

## 📖 Next Steps

1. Read the [README.md](README.md) for more details
2. Check [API.md](API.md) for API documentation
3. Access the dashboard at `http://localhost:8080/dashboard` to create users
4. Use the Swagger UI at `http://localhost:8080/api` to test endpoints

