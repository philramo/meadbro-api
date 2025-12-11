# MeadBro API

A FastAPI-based REST API for the MeadBro mead brewing tracking application.

## Features

### 🔐 Authentication
- WebAuthn passkey authentication
- User registration and login
- Secure session management
- User-specific data isolation

### 🍯 Recipe Management
- CRUD operations for mead recipes
- Real-time OG/ABV calculations using brewing science
- Recipe ingredients with amounts and units
- Yeast configuration tracking
- Recipe validation and sanity checks

### 🧪 Ingredients Management
- Complete ingredient database with CRUD operations
- Type-based categorization system
- Database-driven ingredient types with gravity constants
- Search and filtering capabilities
- User-specific ingredient libraries

### 📊 Brewing Calculations
- Accurate OG/ABV calculations using proper brewing constants
- Water volume calculations based on ingredient densities
- Fermentability-adjusted gravity contributions
- Recipe validation with realistic brewing limits

### 🗄️ Database Management
- SQLite database with proper schema
- User data isolation and security
- Automatic database initialization and migrations
- Ingredient types with gravity constants

## Technology Stack

- **FastAPI** - Modern Python web framework
- **SQLite** - Lightweight database
- **WebAuthn** - Passwordless authentication
- **Pydantic** - Data validation and serialization
- **CORS** - Cross-origin resource sharing

## API Endpoints

### Authentication
- `POST /register` - Register new user with passkey
- `POST /login` - Login with passkey
- `GET /me` - Get current user info

### Recipes
- `GET /recipes` - List user recipes
- `POST /recipes` - Create new recipe
- `PUT /recipes/{id}` - Update recipe
- `DELETE /recipes/{id}` - Delete recipe
- `GET /recipes/{id}` - Get recipe details

### Ingredients
- `GET /ingredients` - List user ingredients (with search/filter)
- `POST /ingredients` - Create new ingredient
- `PUT /ingredients/{id}` - Update ingredient
- `DELETE /ingredients/{id}` - Delete ingredient
- `GET /ingredient-types` - Get available ingredient types

### Brews
- `GET /brews` - List user brews
- `POST /brews` - Create new brew from recipe
- `GET /brews/{id}` - Get brew details with scaling

## Brewing Science

The API uses proper brewing calculations with realistic gravity constants:

| Ingredient Type | Gravity Points per kg/L | Description |
|----------------|------------------------|-------------|
| Honey | 300 | Natural honey from bees |
| Fruit | 50 | Fresh or dried fruits |
| Sugar | 385 | Refined sugar and syrups |
| Grain | 280 | Malted grains and cereals |
| Spices/Acids/etc | 0 | Non-fermentable additives |

### Calculation Formula
```
OG = 1 + (total_gravity_points / 1000)
ABV = (OG - FG) * 131.25
Gravity Points = (ingredient_kg / volume_L) * type_gravity * (fermentability / 100)
```

## Getting Started

### Prerequisites
- Python 3.8+
- pip or poetry

### Installation
```bash
pip install -r requirements.txt
```

### Configuration
Copy `.env.example` to `.env` and configure:
```bash
cp .env.example .env
```

### Development
```bash
python app.py
```
Runs on http://localhost:8000

### Database
SQLite database is automatically created and initialized on first run with:
- User tables for authentication
- Recipe and ingredient schemas
- Ingredient types with brewing constants
- Proper foreign key relationships

## Project Structure

```
meadbro-api/
├── app.py              # Main FastAPI application
├── config.py           # Configuration management
├── requirements.txt    # Python dependencies
├── meadbro.db         # SQLite database (auto-created)
├── cert.pem           # SSL certificate
├── key.pem            # SSL private key
└── .env.example       # Environment template
```

## Security Features

- WebAuthn passwordless authentication
- User data isolation (all queries filtered by user_email)
- HTTPS support with SSL certificates
- CORS configuration for frontend integration
- Input validation with Pydantic models

## Contributing

This is part of the MeadBro brewing tracking system. The API provides secure, scientifically-accurate brewing calculations and data management for mead makers.
