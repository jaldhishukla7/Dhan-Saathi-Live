# Frontend-Backend Connection Guide

This guide explains how the frontend connects to the backend API in the DhanSaathi application.

## Architecture Overview

- **Backend**: FastAPI running on `http://127.0.0.1:8000`
- **Frontend**: React + Vite running on `http://localhost:5173` (default Vite port)
- **Communication**: REST API with JWT authentication

## Configuration

### 1. Environment Variables

The frontend uses environment variables for API configuration:

- Create a `.env` file in the `frontend/` directory (or copy from `.env.example` if it exists):
  ```
  VITE_API_BASE_URL=http://127.0.0.1:8000
  ```

- **Important**: Vite requires the `VITE_` prefix for environment variables to be accessible in the client code.

- For production, update `VITE_API_BASE_URL` to your production API URL.

### 2. API Client Setup

The frontend uses **Axios** as the HTTP client with a centralized configuration:

**File**: `frontend/src/api/axios.ts`

- Base URL: `${VITE_API_BASE_URL}/api`
- Automatic JWT token attachment via request interceptors
- Consistent error handling

### 3. CORS Configuration

The backend is already configured to allow CORS requests:

**File**: `backend/app/main.py`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (adjust for production)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**For Production**: Update `allow_origins` to only include your frontend domain(s).

## How It Works

### 1. Authentication Flow

1. **Registration**: User registers via `POST /api/users/register`
2. **Login**: User logs in via `POST /api/users/login` (OAuth2PasswordRequestForm)
3. **Token Storage**: Access token is stored in `localStorage`
4. **Automatic Attachment**: Axios interceptors automatically attach the token to all requests

### 2. API Service Layer

All API calls go through service functions:

**File**: `frontend/src/services/authService.ts`

- `registerUser()`: Registers a new user
- `loginUser()`: Authenticates and returns JWT token

### 3. Protected Routes

Protected API endpoints require the JWT token in the Authorization header:
```
Authorization: Bearer <token>
```

The axios instance automatically adds this header for all requests.

## Usage Example

```typescript
import { loginUser } from "../services/authService";
import api from "../api/axios";

// Login
const data = await loginUser(email, password);
localStorage.setItem("access_token", data.access_token);

// Make authenticated request
const response = await api.get("/users/me");
```

## Development Setup

1. **Start Backend**:
   ```bash
   cd backend
   uvicorn app.main:app --reload
   ```

2. **Start Frontend**:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

3. **Verify Connection**:
   - Backend should be running on `http://127.0.0.1:8000`
   - Frontend should be running on `http://localhost:5173`
   - Check browser console for any CORS errors

## Troubleshooting

### CORS Errors
- Ensure backend CORS middleware is configured
- Check that backend is running
- Verify API base URL in `.env` matches backend URL

### Authentication Errors
- Verify token is stored in `localStorage`
- Check token expiration (default: 60 minutes)
- Ensure Authorization header is being sent (check Network tab)

### Connection Errors
- Verify backend is running: `http://127.0.0.1:8000`
- Check API endpoints match between frontend and backend
- Review browser console and network tab for detailed error messages

## Next Steps

- Add error interceptors to axios for centralized error handling
- Implement token refresh logic
- Add request/response logging for debugging
- Set up proper environment-specific configurations (dev/staging/prod)

