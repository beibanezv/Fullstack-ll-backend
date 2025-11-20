API specification - minimal endpoints to integrate with the provided frontend

Base URL: http://localhost:5000

Auth

POST /api/auth/register
- Body: { name, email, password }
- Response 201: { user: { id, name, email, is_admin } }
- Error 400: { error }

POST /api/auth/login
- Body: { email, password }
- Response 200: { token, user: { id, name, email, is_admin } }
- Error 400/401

GET /api/auth/profile
- Headers: Authorization: Bearer <token>
- Response 200: { user }

Products

GET /api/products
- Response 200: [ { id, name, description, price, category, image_url, stock } ]

GET /api/products/:id
- Response 200: { product }

POST /api/products
- Headers: Authorization: Bearer <token> (admin)
- Body: { name, description, price, category, image_url, stock }
- Response 201: { product }

PUT /api/products/:id
- Headers: Authorization: Bearer <token> (admin)
- Body: partial fields to update
- Response 200: { product }

DELETE /api/products/:id
- Headers: Authorization: Bearer <token> (admin)
- Response 200: { message }

Contact

POST /api/contact
- Body: { name, email, message }
- Response 201: { id, name, email, message, created_at }

Admin / Users

GET /api/users
- Headers: Authorization: Bearer <token> (admin)
- Response 200: [ { id, name, email, is_admin } ]

PUT /api/users/:id/role
- Headers: Authorization: Bearer <token> (admin)
- Body: { is_admin: true|false }
- Response 200: { id, is_admin }

Notes
- The server reads `DATABASE_URL` from environment (`.env`) to connect to Neon DB.
- JWT secret is read from `JWT_SECRET` environment variable.
- If you prefer the backend to serve the React static build, place the frontend `build` folder at `../frontend_build` (see server README).  

Examples

Register request:
POST /api/auth/register
{ "name": "Juan", "email": "juan@ejemplo.com", "password": "miPass123" }

Login response:
{ "token": "<jwt>", "user": { "id": 1, "name": "Juan", "email": "juan@ejemplo.com", "is_admin": false } }

Product example:
{ "id": 1, "name": "Perfume A", "description": "...", "price": 19990, "category": "Femenino", "image_url": "https://...", "stock": 10 }
