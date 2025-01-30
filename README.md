# Auth Service

This repository provides a basic authentication and account management service built using Go (Golang), Gin for HTTP routing, and PostgreSQL as the persistent store. It supports account registration, authentication (via JWT and API keys), role management, and various account operations like blocking/unblocking, password updates, and soft deletion.

---

## Table of Contents

1. [Features](#features)  
2. [Usage Example](#usage-example)  
3. [How It Works](#how-it-works)  
4. [Workflow Overview](#workflow-overview)  
5. [Potential Improvements](#potential-improvements)  
6. [Getting Started](#getting-started)  
7. [Project Structure](#project-structure)

---

## Features

1. **User Registration**  
   - Validates email, password, and nickname format before creating a new account.
   - Passwords are hashed with `bcrypt`.

2. **Login and JWT-based Authentication**  
   - Issues a JWT token upon successful login.
   - Provides a refresh token endpoint for renewing expired JWTs.

3. **API Key Authentication**  
   - Allows the creation of API keys linked to a user account.
   - Supports expiration dates for API keys.
   - Revocation/deletion of API keys.

4. **Role Management**  
   - Adds or removes roles for any given user account.
   - Fetches all roles for a specific account.
   - Bulk update of roles.

5. **Account Operations**  
   - **Block/Unblock** an account until a specified date.
   - **Delete** (soft delete) an account.
   - **Update** account's password.
   - **Find** accounts or retrieve a single account by email/ID.

6. **Database Table Creation**  
   - Automatically ensures required tables exist at startup:
     - `account`
     - `account_roles`
     - `api_keys`

---

## Usage Example

Below are brief examples of how you might interact with some of the API endpoints using `curl`. Assume your service is running locally on port `:5000`.

### Register a new account:

**Request**

```bash
curl -X POST http://localhost:5000/api/v1/auth/add \
    -H "Content-Type: application/json" \
    -d '{
        "email": "john@example.com",
        "password": "MyStr0ngP@ss",
        "nickname": "john"
    }'
```

**Response:**

```json
{
    "message": "account registered successfully"
}
```

### Log in and get a JWT token:

**Request**

```bash
curl -X POST http://localhost:5000/api/v1/auth/login \
    -H "Content-Type: application/json" \
    -d '{
        "email": "john@example.com",
        "password": "MyStr0ngP@ss"
        }'
```

**Response:**

```json
{
    "token": "<JWT_TOKEN>"
}
```

### Refresh an existing JWT token:

**Request**

```bash
curl -X POST http://localhost:5000/api/v1/auth/refresh \
    -H "Authorization: Bearer <REFRESH_TOKEN>"
```

**Response:**

```json
{
    "token": "<NEW_JWT_TOKEN>"
}
```

### Authenticate via API Key:

**Request**

```bash
# First, create an API key for a specific account
curl -X POST http://localhost:5000/api/v1/auth/api-key/<ACCOUNT_ID> \
    -H "Content-Type: application/json" \
    -d '{
        "expires_at": "2025-12-31T23:59:59Z"
    }'

# Assume the API Key returned is <API_KEY_VALUE>
# Now authenticate with the key:
curl -X GET http://localhost:5000/api/v1/auth/authenticate \
    -H "Authorization: Bearer <API_KEY_VALUE>"
```

**Response:**

```json
{
    "account_id": "<UUID>",
    "email": "john@example.com",
    "roles": ["admin", "user"]
}
```

### Add a Role to an Account:

**Request**

```bash
curl -X POST http://localhost:5000/api/v1/auth/roles/add/<ACCOUNT_ID> \
    -H "Content-Type: application/json" \
    -d '{
        "role": "editor"
    }'
```

**Response:**

```json
{
    "message": "role added to account successfully"
}
```

## How It Works

1. **Environment Variables**

    - `DB_CLIENT`: Connection string for PostgreSQL (e.g., `postgres://user:pass@host:port/dbname?sslmode=disable`).
    - `JWT_SECRET`: Secret key for signing JWT tokens.

2. **Database Schema**

    - `account` table stores primary account info (id, nickname, email, password hash, timestamps, etc.).
    - `account_roles` table stores the many-to-many relationship between accounts and roles.
    - `api_keys` table stores API key records, each referencing a single account.
    -  Tables are automatically created (if they don't exist) when the service starts.

3. **Authentication**

    - **JWT**
        On login, we verify user credentials and create a JWT token with a 24-hour expiry.
        Token includes account ID, nickname, and roles.
        We can refresh expired tokens via the `/api/v1/auth/refresh` endpoint.

    - **API Key**
        We generate a random API key (hex-encoded 32 bytes).
        Each API key can optionally have an expiration date.
        The key can be passed in the Authorization header to authenticate.

4. **Account Management**

    - **Registration** checks for existing email usage and password complexity.
    - **Blocking/Unblocking** sets or clears a blocked timestamp in the account table.
    - **Deleting** sets a deleted flag (soft delete).
    - **Password Updates** use bcrypt to store hashed passwords in the DB.

## Workflow Overview

### Here is a high-level workflow:

1. **Startup** (`app.Start()`):
    - Open the Postgres connection (using `DB_CLIENT`).
    - Initialize repository implementations.
    - Create service layer instances.
    - Set up Gin routes for public and protected endpoints.
    - Ensure Tables Exist by creating them if they do not.
    - Start listening on `:5000`.

2. **Registration** (`POST /api/v1/auth/add`):
    - Validate request body (email, password, nickname).
    - Hash password with bcrypt.
    - Save the new account record in the DB.

3. **Login** (`POST /api/v1/auth/login`):
    - Verify credentials.
    - Check if the account is blocked or deleted.
    - Return signed JWT if valid.

4. **Refresh Token** (`POST /api/v1/auth/refresh`):
    - Validate the provided refresh token.
    - Check account is not blocked or deleted.
    - Return a new JWT.

5. **API Key Management:**
    - **Create** (`POST /api/v1/auth/api-key/:account_id`):
        - Generate random bytes and store them as an API key in the DB.
    - **Delete** (`DELETE /api/v1/auth/delete/api-key`):
        - Remove the API key from the DB.

6. **Role Management:**
    - **Add/Remove** (`POST /roles/add/:account_id, POST /roles/delete/:account_id`).
    - **Bulk Update** (`POST /edit-roles`): 
        - Update roles across multiple accounts based on a JSON structure.

7. **Account Operations:**
    - **Block/Unblock:** Set or clear `blocked` time for a user.
    - **Delete:** Soft delete (mark `deleted` as `true`).
    - **Update Password:** Replace `password` with a new hashed password if the old one matches.

## Potential Improvements

### Enhanced Security

- Rate limiting to prevent brute force attacks on login.
- Further improvements on password hashing (adjust bcrypt cost, add pepper, tc.).
- Add multi-factor authentication.

### Refresh Token Storage
- Implement a refresh token store with revocation capabilities for better control over token usage.

### Audit Logging
- Log all changes made to user accounts, password updates, role changes, etc.

### Performance and Monitoring
- Ad metrics (e.g., Prometheus) and health checks for better observability.
- Use caching layers for frequently accessed data, if needed.

### Code Organization & Testing
- Add unit tests and integration tests to ensure reliability.
- Add testing tools for future and already existing test cases.
- Implement a CI/CD pipeline with code coverage and static analysis checks.

## Getting Started

### Clone the Repository
```bash
git clone https://github.com/demkowo/auth.git
cd auth
```

### Set Environment Variables

```bash
export DB_CLIENT="postgres://user:password@localhost:5432/authdb?sslmode=disable"
export JWT_SECRET="some-secret-key"
```

### Run the Service

```bash
go mod tidy
go run main.go
```

By default, the service listens on port :5000.

### Check Database Setup

- On startup, logs will indicate the creation or existence of the `account`, `account_roles`, and `api_keys` tables.

### Test the Endpoints

- Use a tool like `curl` or Postman to interact with the service.

## Project Structure

```bash
.
├── app
│   ├── app.go             # Main entrypoint logic (DB connection, router setup)
│   ├── auth_routes.go     # Defines public & protected routes
│   └── create_tables.go   # Ensures required tables exist
├── config
│   └── config.go          # Loads environment variables (JWT secret)
├── handlers
│   └── auth_handler.go    # Gin handlers for each auth/account operation
├── models
│   └── auth_model.go      # Data models (Account, AccountRoles, APIKey)
├── repositories
│   └── auth_repository.go # PostgreSQL queries for account & API key management
├── services
│   └── auth_service.go    # Core business logic (validations, hashing, token generation)
└── main.go                # Typically references app.Start() to launch the server
```