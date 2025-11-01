from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from app.routes import user_routes as user_router

app = FastAPI(
    title="DhanSaathi API",
    version="1.0.0",
    description="API for authentication and user management"
)

# ---------- MIDDLEWARE ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- ROUTERS ----------
app.include_router(user_router.router, prefix="/api/users")

# ---------- ROOT ROUTE ----------
@app.get("/")
def read_root():
    return {"message": "Welcome to DhanSaathi API"}


# ---------- CUSTOM OPENAPI (Swagger UI with Bearer Auth) ----------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    # Apply BearerAuth only to protected routes
    protected_paths = [
        "/api/users/users",
        "/api/users/users/{user_id}",
        "/api/users/me"
    ]

    for path, path_item in openapi_schema["paths"].items():
        if path in protected_paths:
            for method in path_item.values():
                method["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi