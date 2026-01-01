import api from "../api/axios";

/**
 * Register a new user
 */
export async function registerUser(username: string, email: string, password: string) {
  const response = await api.post("/users/register", {
    username,
    email,
    password,
  });
  return response.data;
}

/**
 * Login user using FastAPI OAuth2PasswordRequestForm
 * Note: FastAPI OAuth2PasswordRequestForm expects form-urlencoded data
 */
export async function loginUser(email: string, password: string) {
  // Create form-urlencoded data for OAuth2PasswordRequestForm
  const formData = new URLSearchParams();
  formData.append("username", email); // FastAPI expects "username" field
  formData.append("password", password);

  const response = await api.post(
    "/users/login",
    formData.toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );

  return response.data;
}
