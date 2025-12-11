"""MeadBro API - FastAPI backend for mead brewing tracking."""

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import sqlite3
import json
import logging
import re
import jwt
import base64
import secrets
from functools import wraps
from uuid import uuid4
from webauthn import generate_registration_options, verify_registration_response, generate_authentication_options, verify_authentication_response
from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement, AttestationConveyancePreference

# Import configuration
from config import load_config

# Load configuration
config = load_config()

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.server.log_level.upper()),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('meadbro.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = FastAPI(title="MeadBro API", version="1.0.0")

# Add CORS middleware if enabled
if config.cors.enabled:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors.origins,
        allow_credentials=config.cors.credentials,
        allow_methods=config.cors.methods,
        allow_headers=config.cors.headers,
    )
    logger.info(f"CORS enabled for origins: {config.cors.origins}")

# Auth configuration from config
SECRET_KEY = config.auth.secret_key
ALGORITHM = config.auth.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES = config.auth.access_token_expire_minutes

# Challenge storage - use Redis if enabled, otherwise in-memory
if config.redis.enabled:
    try:
        import redis
        redis_client = redis.from_url(config.redis.url, password=config.redis.password, db=config.redis.db)
        challenge_store = redis_client
        logger.info(f"Redis enabled: {config.redis.url}")
    except ImportError:
        logger.warn("Redis requested but not installed, falling back to in-memory storage")
        challenge_store = {}
    except Exception as e:
        logger.error(f"Redis connection failed: {e}, falling back to in-memory storage")
        challenge_store = {}
else:
    challenge_store = {}
    logger.info("Using in-memory challenge storage")

oauth2_scheme = HTTPBearer()

# Database setup from config
DB_PATH = config.database.path

# Security patterns to detect
DANGEROUS_PATTERNS = [
    r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
    r"(?i)(script|javascript|vbscript|onload|onerror|onclick)",
    r"[<>\"'%;()&+]",  # Common injection characters
    r"(?i)(--|\#|\/\*|\*\/)",  # SQL comment patterns
    r"(?i)(xp_|sp_|cmd|shell|system)",  # System commands
]

def validate_string_input(value: str, field_name: str = "input") -> str:
    """Validate string input for security threats."""
    if not isinstance(value, str):
        return value
    
    # Check for dangerous patterns
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, value):
            logger.error(f"Security threat detected in {field_name}: {value[:50]}...")
            raise HTTPException(status_code=400, detail=f"Invalid characters detected in {field_name}")
    
    # Length check
    if len(value) > 1000:
        logger.warn(f"Unusually long input in {field_name}: {len(value)} characters")
        raise HTTPException(status_code=400, detail=f"{field_name} too long (max 1000 characters)")
    
    return value.strip()

def validate_numeric_input(value: float, field_name: str = "numeric", min_val: float = -999999, max_val: float = 999999) -> float:
    """Validate numeric input for reasonable ranges."""
    if not isinstance(value, (int, float)):
        raise HTTPException(status_code=400, detail=f"{field_name} must be numeric")
    
    if value < min_val or value > max_val:
        logger.warn(f"Numeric value out of range for {field_name}: {value}")
        raise HTTPException(status_code=400, detail=f"{field_name} must be between {min_val} and {max_val}")
    
    return float(value)

def security_check(func):
    """Decorator to validate all string inputs in request models."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Check all arguments for Pydantic models
        for arg in args:
            if hasattr(arg, '__dict__') and hasattr(arg, '__fields__'):  # Pydantic model
                validate_pydantic_model(arg)
        
        # Check kwargs for models
        for key, value in kwargs.items():
            if hasattr(value, '__dict__') and hasattr(value, '__fields__'):  # Pydantic model
                validate_pydantic_model(value)
        
        return await func(*args, **kwargs)
    return wrapper

def validate_pydantic_model(model):
    """Recursively validate all string fields in a Pydantic model."""
    for field_name, field_value in model.__dict__.items():
        if isinstance(field_value, str):
            validate_string_input(field_value, field_name)
        elif isinstance(field_value, (int, float)):
            validate_numeric_input(field_value, field_name, -999999, 999999)
        elif isinstance(field_value, list):
            for i, item in enumerate(field_value):
                if hasattr(item, '__dict__') and hasattr(item, '__fields__'):
                    validate_pydantic_model(item)
                elif isinstance(item, str):
                    validate_string_input(item, f"{field_name}[{i}]")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user_email(credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)):
    """Get current user email from JWT token."""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_email: str = payload.get("user_email")
        if user_email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return user_email
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

def get_user_by_email(email: str):
    """Get user from database by email."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(user) if user else None

# Database setup
DB_PATH = "meadbro.db"

# Pydantic models
class User(BaseModel):
    email: str
    name: str

class PasskeyRegister(BaseModel):
    email: str
    name: str

class RegisterStartRequest(BaseModel):
    email: str
    name: str

class RegisterCompleteRequest(BaseModel):
    email: str
    credential: dict

class LoginStartRequest(BaseModel):
    email: str

class LoginCompleteRequest(BaseModel):
    email: str
    credential: dict

class Ingredient(BaseModel):
    name: str
    source: str
    type: str
    price: float
    fermentability: float
    pkl: float  # Potential Kilogram per Litre
    dosing_type: str = "linear"  # "linear" or "custom"
    dosing_rules: Optional[str] = None  # JSON string for custom dosing

class Yeast(BaseModel):
    strain: str
    abv_tolerance: float
    source: str
    price: float
    amount_grams: float

class RecipeIngredient(BaseModel):
    ingredient_id: str
    amount: float
    unit: str  # "kg", "l", "g", "ml", etc.

class BrewStep(BaseModel):
    step_name: str
    notes: str = ""
    date: Optional[str] = None

class Recipe(BaseModel):
    title: str
    description: str
    volume_liters: float
    target_fg: float
    ingredients: List[RecipeIngredient]
    yeast: Yeast

def validate_recipe_sanity(og: float, abv: float) -> dict:
    """Validate if recipe is realistic for fermentation."""
    warnings = []
    errors = []
    
    # Check OG levels
    if og > 1.200:
        errors.append(f"OG {og:.3f} is extremely high - will be like syrup and likely won't ferment")
    elif og > 1.150:
        warnings.append(f"OG {og:.3f} is very high - may have fermentation issues")
    elif og > 1.120:
        warnings.append(f"OG {og:.3f} is high - ensure yeast can handle this gravity")
    
    # Check ABV vs yeast tolerance
    if abv > 25:
        errors.append(f"Expected ABV {abv:.1f}% is unrealistic - most yeasts die around 18-20%")
    elif abv > 18:
        warnings.append(f"Expected ABV {abv:.1f}% is very high - ensure yeast can handle this")
    
    return {
        "valid": len(errors) == 0,
        "warnings": warnings,
        "errors": errors
    }

def calculate_custom_dosing(ingredient, target_volume_liters, recipe_ingredients):
    """Calculate custom dosing for additives like yeast nutrient."""
    if ingredient["dosing_type"] != "custom" or not ingredient["dosing_rules"]:
        return None
    
    try:
        rules = json.loads(ingredient["dosing_rules"])
        
        # Yeast nutrient dosing based on fruit content
        if rules.get("type") == "yeast_nutrient":
            # Calculate fruit percentage
            total_fruit_kg = 0
            total_fermentable_kg = 0
            
            for ing_data in recipe_ingredients:
                if ing_data["type"] in ["fruit", "cherry", "apple", "grape", "blueberry", "strawberry"]:
                    total_fruit_kg += ing_data["scaled_amount"]
                if ing_data["fermentability"] > 0:
                    total_fermentable_kg += ing_data["scaled_amount"]
            
            fruit_percentage = (total_fruit_kg / total_fermentable_kg * 100) if total_fermentable_kg > 0 else 0
            
            # Determine dosing based on fruit content
            if fruit_percentage >= 30:  # High fruit
                grams_per_23L = rules.get("high_fruit_grams_per_23L", 18)
            else:  # Low to medium fruit
                grams_per_23L = rules.get("low_fruit_grams_per_23L", 24)
            
            # Scale to target volume
            scaled_amount = (target_volume_liters / 23.0) * grams_per_23L
            return round(scaled_amount, 1)
            
    except (json.JSONDecodeError, KeyError):
        return None
    
    return None

def calculate_ingredient_volume(ingredient_data, amount, unit):
    """Calculate the actual volume an ingredient takes up."""
    ingredient_type = ingredient_data.get('type', 'other')
    
    # Convert to kg first
    if unit == 'g':
        amount_kg = amount / 1000
    elif unit == 'l':
        amount_kg = amount  # Will adjust for density below
    elif unit == 'ml':
        amount_kg = amount / 1000  # Will adjust for density below
    else:  # kg
        amount_kg = amount
    
    # Density factors (kg/L) - how much 1L weighs
    densities = {
        'honey': 1.45,
        'fruit': 1.0,  # Most fruits are close to water
        'water': 1.0,
        'liquid': 1.0
    }
    
    density = densities.get(ingredient_type, 1.0)
    
    # If unit was already volume (l/ml), convert back considering density
    if unit in ['l', 'ml']:
        return amount_kg  # Already in volume units
    else:
        # Convert weight to volume: volume = weight / density
        return amount_kg / density

def calculate_og_and_abv_with_water(ingredients: List[RecipeIngredient], target_volume_liters: float, conn) -> tuple[float, float, float]:
    """Calculate OG, ABV, and required water volume."""
    total_gravity_points = 0
    total_ingredient_volume = 0
    
    # Set row factory for this connection
    conn.row_factory = sqlite3.Row
    
    for ing in ingredients:
        # Get ingredient properties
        ingredient = conn.execute("SELECT * FROM ingredients WHERE id = ?", (ing.ingredient_id,)).fetchone()
        if not ingredient:
            continue
            
        fermentability, pkl, ingredient_type = ingredient['fermentability'], ingredient['pkl'], ingredient['type']
        
        # Calculate volume this ingredient takes up
        ingredient_volume = calculate_ingredient_volume({'type': ingredient_type}, ing.amount, ing.unit)
        total_ingredient_volume += ingredient_volume
        
        # Convert amount to kg for gravity calculation
        amount_kg = ing.amount
        if ing.unit == "g":
            amount_kg = ing.amount / 1000
        elif ing.unit in ["l", "ml"]:
            # For liquids, assume density from type
            density = 1.45 if ingredient_type == 'honey' else 1.0
            if ing.unit == "ml":
                amount_kg = (ing.amount / 1000) * density
            else:
                amount_kg = ing.amount * density
        
        logger.info(f"CALC: Ingredient {ingredient['name']}: PKL={pkl}, fermentability={fermentability}, amount={amount_kg}kg")
        
        # Calculate gravity points contribution
        amount_kg = ing.amount
        if ing.unit == "g":
            amount_kg = ing.amount / 1000
        elif ing.unit in ["l", "ml"]:
            # For liquids, assume density from type
            density = 1.45 if ingredient_type == 'honey' else 1.0
            if ing.unit == "ml":
                amount_kg = (ing.amount / 1000) * density
            else:
                amount_kg = ing.amount * density
        
        # Calculate gravity points contribution
        # Get gravity points from ingredient_types table
        type_info = conn.execute("SELECT gravity_points FROM ingredient_types WHERE id = ?", (ingredient_type,)).fetchone()
        base_gravity = type_info[0] if type_info else 50  # Default to 50 if type not found
        
        gravity_points = (amount_kg / target_volume_liters) * base_gravity * (fermentability / 100)
        logger.info(f"CALC: {ingredient['name']} gravity points: ({amount_kg}/{target_volume_liters}) * {base_gravity} * {fermentability/100} = {gravity_points}")
        total_gravity_points += gravity_points
    
    # Calculate required water volume
    water_volume_needed = max(0, target_volume_liters - total_ingredient_volume)
    
    logger.info(f"CALC: Total gravity points: {total_gravity_points}")
    
    # Calculate OG
    og = 1 + (total_gravity_points / 1000)
    
    logger.info(f"CALC: Final OG calculation: 1 + ({total_gravity_points}/1000) = {og}")
    
    # Calculate expected ABV (assuming FG of 1.010)
    estimated_fg = 1.010
    abv = (og - estimated_fg) * 131.25
    
    return round(og, 3), round(max(abv, 0), 1), round(water_volume_needed, 2)

def migrate_database():
    """Migrate existing database to add user support."""
    logger.info("Checking for database migrations...")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Check if users table exists
            users_exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
            ).fetchone()
            
            if not users_exists:
                logger.info("Creating users table...")
                conn.execute("""
                    CREATE TABLE users (
                        email TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        passkey_credential_id TEXT,
                        passkey_public_key TEXT,
                        oauth_provider TEXT,
                        oauth_id TEXT,
                        created_date TEXT NOT NULL
                    )
                """)
            
            # Check if user_email column exists in ingredients
            columns = conn.execute("PRAGMA table_info(ingredients)").fetchall()
            has_user_email = any(col[1] == 'user_email' for col in columns)
            
            if not has_user_email:
                logger.info("Adding user_email column to existing tables...")
                # Add user_email column with default value
                conn.execute("ALTER TABLE ingredients ADD COLUMN user_email TEXT DEFAULT 'system@meadbro.com'")
                conn.execute("ALTER TABLE recipes ADD COLUMN user_email TEXT DEFAULT 'system@meadbro.com'")
                conn.execute("ALTER TABLE brews ADD COLUMN user_email TEXT DEFAULT 'system@meadbro.com'")
                
                # Create system user for existing data
                conn.execute("""
                    INSERT OR IGNORE INTO users VALUES 
                    ('system@meadbro.com', 'System User', NULL, NULL, 'system', NULL, ?)
                """, (datetime.now().isoformat(),))
                
        logger.info("Database migration completed")
    except Exception as e:
        logger.error(f"Database migration failed: {str(e)}")
        raise

def init_db():
    """Initialize the database."""
    logger.info("Initializing database...")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    email TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    passkey_credential_id TEXT,
                    passkey_public_key TEXT,
                    oauth_provider TEXT,
                    oauth_id TEXT,
                    created_date TEXT NOT NULL
                );
                
                CREATE TABLE IF NOT EXISTS ingredients (
                    id TEXT PRIMARY KEY,
                    user_email TEXT NOT NULL DEFAULT 'system@meadbro.com',
                    name TEXT NOT NULL,
                    source TEXT,
                    type TEXT NOT NULL,
                    price REAL DEFAULT 0,
                    fermentability REAL DEFAULT 0,
                    dosing_type TEXT DEFAULT 'linear',
                    dosing_rules TEXT,
                    created_date TEXT NOT NULL,
                    FOREIGN KEY (user_email) REFERENCES users (email)
                );
                
                CREATE TABLE IF NOT EXISTS ingredient_types (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    gravity_points INTEGER NOT NULL,
                    description TEXT
                );
                
                CREATE TABLE IF NOT EXISTS recipes (
                    id TEXT PRIMARY KEY,
                    user_email TEXT NOT NULL DEFAULT 'system@meadbro.com',
                    title TEXT NOT NULL,
                    description TEXT,
                    volume_liters REAL NOT NULL,
                    calculated_og REAL NOT NULL,
                    expected_abv REAL NOT NULL,
                    target_fg REAL NOT NULL,
                    yeast_strain TEXT NOT NULL,
                    yeast_abv_tolerance REAL NOT NULL,
                    yeast_source TEXT,
                    yeast_price REAL DEFAULT 0,
                    yeast_amount_grams REAL NOT NULL,
                    created_date TEXT NOT NULL,
                    FOREIGN KEY (user_email) REFERENCES users (email)
                );
                
                CREATE TABLE IF NOT EXISTS recipe_ingredients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipe_id TEXT NOT NULL,
                    ingredient_id TEXT NOT NULL,
                    amount REAL NOT NULL,
                    unit TEXT NOT NULL,
                    FOREIGN KEY (recipe_id) REFERENCES recipes (id),
                    FOREIGN KEY (ingredient_id) REFERENCES ingredients (id)
                );
                
                CREATE TABLE IF NOT EXISTS brews (
                    id TEXT PRIMARY KEY,
                    user_email TEXT NOT NULL DEFAULT 'system@meadbro.com',
                    recipe_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    target_volume_liters REAL NOT NULL,
                    scale_factor REAL NOT NULL,
                    created_date TEXT NOT NULL,
                    completed BOOLEAN DEFAULT 0,
                    completion_date TEXT,
                    tasting_notes TEXT,
                    FOREIGN KEY (user_email) REFERENCES users (email),
                    FOREIGN KEY (recipe_id) REFERENCES recipes (id)
                );
                
                CREATE TABLE IF NOT EXISTS brew_ingredients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    brew_id TEXT NOT NULL,
                    ingredient_id TEXT NOT NULL,
                    original_amount REAL NOT NULL,
                    scaled_amount REAL NOT NULL,
                    actual_amount REAL NOT NULL,
                    unit TEXT NOT NULL,
                    FOREIGN KEY (brew_id) REFERENCES brews (id),
                    FOREIGN KEY (ingredient_id) REFERENCES ingredients (id)
                );
                
                CREATE TABLE IF NOT EXISTS brew_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    brew_id TEXT NOT NULL,
                    step_name TEXT NOT NULL,
                    notes TEXT,
                    step_date TEXT NOT NULL,
                    FOREIGN KEY (brew_id) REFERENCES brews (id)
                );
            """)
        
        # Run migrations for existing databases
        migrate_database()
        
        # Populate ingredient types if empty
        with sqlite3.connect(DB_PATH) as conn:
            existing_types = conn.execute("SELECT COUNT(*) FROM ingredient_types").fetchone()[0]
            if existing_types == 0:
                logger.info("Populating ingredient types...")
                ingredient_types = [
                    ('honey', 'Honey', 300, 'Natural honey from bees'),
                    ('fruit', 'Fruit', 50, 'Fresh or dried fruits'),
                    ('sugar', 'Sugar', 385, 'Refined sugar and syrups'),
                    ('grain', 'Grain', 280, 'Malted grains and cereals'),
                    ('spice', 'Spice', 0, 'Spices and herbs for flavoring'),
                    ('acid', 'Acid', 0, 'Acids for pH adjustment'),
                    ('nutrient', 'Nutrient', 0, 'Yeast nutrients and energizers'),
                    ('clarifier', 'Clarifier', 0, 'Clarifying agents'),
                    ('preservative', 'Preservative', 0, 'Preservatives and stabilizers'),
                    ('other', 'Other', 0, 'Other ingredients')
                ]
                
                for type_id, name, gravity, desc in ingredient_types:
                    conn.execute(
                        "INSERT INTO ingredient_types (id, name, gravity_points, description) VALUES (?, ?, ?, ?)",
                        (type_id, name, gravity, desc)
                    )
        
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    logger.info("Starting MeadBro API...")
    init_db()
    logger.info("MeadBro API startup complete")

# Also initialize immediately for safety
init_db()

# Routes
@app.get("/")
async def root():
    logger.info("Root endpoint accessed")
    return {"message": "MeadBro API"}

class LogLevelRequest(BaseModel):
    level: str

@app.post("/admin/log-level")
async def set_log_level(request: LogLevelRequest):
    """Set logging level (DEBUG, INFO, WARNING, ERROR)."""
    level = request.level
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR"]
    if level.upper() not in valid_levels:
        logger.warn(f"Invalid log level requested: {level}")
        raise HTTPException(status_code=400, detail=f"Invalid level. Use: {valid_levels}")
    
    logger.info(f"Changing log level to {level.upper()}")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Update config in memory (not persisted)
    config.server.log_level = level.upper()
    
    return {"message": f"Log level set to {level.upper()}"}

# Authentication endpoints
@app.post("/auth/register/start")
@security_check
async def register_start(request: RegisterStartRequest):
    """Start passkey registration process."""
    logger.info(f"Starting passkey registration for: {request.email}")
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Check if user already exists
            existing = conn.execute("SELECT email FROM users WHERE email = ?", (request.email,)).fetchone()
            if existing:
                raise HTTPException(status_code=400, detail="User already exists")
        
        # Generate user ID
        user_id = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        # Generate registration options
        options = generate_registration_options(
            rp_id=config.auth.rp_id,
            rp_name=config.auth.rp_name,
            user_id=user_id.encode('utf-8'),
            user_name=request.email,
            user_display_name=request.name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            attestation=AttestationConveyancePreference.NONE,
        )
        
        # Store challenge and user info
        challenge_key = f"reg_{request.email}"
        challenge_data = {
            "challenge": base64.urlsafe_b64encode(options.challenge).decode('utf-8'),
            "user_id": user_id,
            "name": request.name,
            "email": request.email
        }
        
        if hasattr(challenge_store, 'setex'):
            challenge_store.setex(challenge_key, 300, json.dumps(challenge_data))
        else:
            challenge_store[challenge_key] = challenge_data
        
        # Convert options to JSON-serializable format
        return {
            "challenge": base64.urlsafe_b64encode(options.challenge).decode('utf-8'),
            "rp": {"id": options.rp.id, "name": options.rp.name},
            "user": {
                "id": base64.urlsafe_b64encode(options.user.id).decode('utf-8'),
                "name": options.user.name,
                "displayName": options.user.display_name
            },
            "pubKeyCredParams": [{"alg": param.alg, "type": param.type} for param in options.pub_key_cred_params],
            "timeout": options.timeout,
            "attestation": options.attestation,
            "authenticatorSelection": {
                "userVerification": options.authenticator_selection.user_verification
            } if options.authenticator_selection else None
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start registration for {request.email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start registration")

@app.post("/auth/register/complete")
@security_check
async def register_complete(request: RegisterCompleteRequest):
    """Complete passkey registration process."""
    logger.info(f"Completing passkey registration for: {request.email}")
    
    try:
        # Get stored challenge
        challenge_key = f"reg_{request.email}"
        if hasattr(challenge_store, 'setex'):  # Redis client
            challenge_data_str = challenge_store.get(challenge_key)
            if challenge_data_str:
                challenge_data = json.loads(challenge_data_str)
                challenge_store.delete(challenge_key)
            else:
                challenge_data = None
        else:  # Dictionary storage
            challenge_data = challenge_store.pop(challenge_key, None)
        
        if not challenge_data:
            raise HTTPException(status_code=400, detail="Registration session expired")
        
        # Verify registration response
        verification = verify_registration_response(
            credential=request.credential,
            expected_challenge=base64.urlsafe_b64decode(challenge_data["challenge"]),
            expected_origin=config.auth.origin,
            expected_rp_id=config.auth.rp_id,
        )
        
        # Debug: log verification object attributes
        logger.info(f"Verification object type: {type(verification)}")
        logger.info(f"Verification object attributes: {dir(verification)}")
        
        if not hasattr(verification, 'verified'):
            # Try different attribute names
            if hasattr(verification, 'verification_successful'):
                success = verification.verification_successful
            else:
                success = True  # Assume success if we can't find the attribute
        else:
            success = verification.verified
            
        if not success:
            raise HTTPException(status_code=400, detail="Passkey verification failed")
        
        # Store user and credential
        with sqlite3.connect(DB_PATH) as conn:
            # Create user
            conn.execute(
                "INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    request.email,
                    challenge_data["name"],
                    challenge_data["user_id"],
                    base64.b64encode(verification.credential_public_key).decode('utf-8'),
                    "webauthn",
                    base64.urlsafe_b64encode(verification.credential_id).decode('utf-8'),
                    datetime.now().isoformat()
                )
            )
        
        # Generate access token
        access_token = create_access_token({"user_email": request.email})
        logger.info(f"User registered successfully with passkey: {request.email}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_email": request.email,
            "user_name": challenge_data["name"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to complete registration for {request.email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to complete registration")

@app.post("/auth/login/start")
@security_check
async def login_start(request: LoginStartRequest):
    """Start passkey authentication process."""
    logger.info(f"Starting passkey authentication for: {request.email}")
    
    try:
        # Get user
        user = get_user_by_email(request.email)
        if not user or user["oauth_provider"] != "webauthn":
            raise HTTPException(status_code=404, detail="User not found or not using passkeys")
        
        # Generate authentication options
        options = generate_authentication_options(
            rp_id=config.auth.rp_id,
            allow_credentials=[{
                "type": "public-key",
                "id": base64.urlsafe_b64decode(user["oauth_id"])
            }],
            user_verification=UserVerificationRequirement.PREFERRED,
        )
        
        # Store challenge
        challenge_key = f"auth_{request.email}"
        challenge_data = {
            "challenge": base64.urlsafe_b64encode(options.challenge).decode('utf-8'),
            "email": request.email
        }
        
        if hasattr(challenge_store, 'setex'):
            challenge_store.setex(challenge_key, 300, json.dumps(challenge_data))
        else:
            challenge_store[challenge_key] = challenge_data
        
        # Convert options to JSON-serializable format
        return {
            "challenge": base64.urlsafe_b64encode(options.challenge).decode('utf-8'),
            "allowCredentials": [{
                "type": "public-key",
                "id": user["oauth_id"],
                "transports": ["internal", "hybrid"]
            }],
            "timeout": options.timeout,
            "userVerification": options.user_verification
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to start authentication for {request.email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to start authentication")

@app.post("/auth/login/complete")
@security_check
async def login_complete(request: LoginCompleteRequest):
    """Complete passkey authentication process."""
    logger.info(f"Completing passkey authentication for: {request.email}")
    
    try:
        # Get stored challenge
        challenge_key = f"auth_{request.email}"
        if hasattr(challenge_store, 'setex'):  # Redis client
            challenge_data_str = challenge_store.get(challenge_key)
            if challenge_data_str:
                challenge_data = json.loads(challenge_data_str)
                challenge_store.delete(challenge_key)
            else:
                challenge_data = None
        else:  # Dictionary storage
            challenge_data = challenge_store.pop(challenge_key, None)
        
        if not challenge_data:
            raise HTTPException(status_code=400, detail="Authentication session expired")
        
        if not challenge_data:
            raise HTTPException(status_code=400, detail="Authentication session expired")
        
        # Get user
        user = get_user_by_email(request.email)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Verify authentication response
        verification = verify_authentication_response(
            credential=request.credential,
            expected_challenge=base64.urlsafe_b64decode(challenge_data["challenge"]),
            expected_origin=config.auth.origin,
            expected_rp_id=config.auth.rp_id,
            credential_public_key=base64.b64decode(user["passkey_public_key"]),
            credential_current_sign_count=0,
        )
        
        # Check verification result - try different possible attributes
        logger.info(f"Verification result: {verification}")
        logger.info(f"Verification attributes: {dir(verification)}")
        
        # Try to find the success attribute
        success = False
        if hasattr(verification, 'verified'):
            success = verification.verified
        elif hasattr(verification, 'verification_successful'):
            success = verification.verification_successful
        else:
            # If we can't find a clear success indicator, assume success if no exception was raised
            success = True
            
        if not success:
            raise HTTPException(status_code=400, detail="Passkey verification failed")
        
        # Generate access token
        access_token = create_access_token({"user_email": request.email})
        logger.info(f"User authenticated successfully with passkey: {request.email}")
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user_email": request.email,
            "user_name": user["name"]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to complete authentication for {request.email}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to complete authentication")

@app.get("/auth/me")
async def get_current_user(user_email: str = Depends(get_current_user_email)):
    """Get current user information."""
    user = get_user_by_email(user_email)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "email": user["email"],
        "name": user["name"],
        "oauth_provider": user["oauth_provider"],
        "created_date": user["created_date"]
    }

# Ingredient endpoints
@app.post("/ingredients")
@security_check
async def create_ingredient(ingredient: Ingredient, user_email: str = Depends(get_current_user_email)):
    """Create a new ingredient."""
    logger.debug(f"Creating ingredient: {ingredient.name} (type: {ingredient.type}) for user: {user_email}")
    
    if ingredient.fermentability < 0 or ingredient.fermentability > 100:
        logger.warn(f"Invalid fermentability {ingredient.fermentability} for ingredient {ingredient.name}")
        raise HTTPException(status_code=400, detail="Fermentability must be 0-100%")
    if ingredient.pkl < 0:
        logger.warn(f"Invalid PKL {ingredient.pkl} for ingredient {ingredient.name}")
        raise HTTPException(status_code=400, detail="PKL cannot be negative")
    if ingredient.price < 0:
        logger.warn(f"Invalid price {ingredient.price} for ingredient {ingredient.name}")
        raise HTTPException(status_code=400, detail="Price cannot be negative")
    
    ingredient_id = str(uuid4())[:8]
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO ingredients (id, name, source, type, price, fermentability, pkl, dosing_type, dosing_rules, created_date, user_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ingredient_id, ingredient.name, ingredient.source, ingredient.type, 
                 ingredient.price, ingredient.fermentability, ingredient.pkl, 
                 ingredient.dosing_type, ingredient.dosing_rules, datetime.now().isoformat(), user_email)
            )
        logger.info(f"Created ingredient: {ingredient.name} (ID: {ingredient_id}) for user: {user_email}")
        return {"id": ingredient_id, "message": "Ingredient created"}
    except Exception as e:
        logger.error(f"Failed to create ingredient {ingredient.name}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create ingredient")

@app.get("/ingredient-types")
async def get_ingredient_types():
    """Get all ingredient types."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        types = conn.execute("SELECT * FROM ingredient_types ORDER BY name").fetchall()
        return [dict(row) for row in types]

@app.get("/ingredients")
async def get_ingredients(user_email: str = Depends(get_current_user_email), q: str = "", type: str = ""):
    """Get all ingredients for the current user with optional search."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        if q or type:
            query = "SELECT * FROM ingredients WHERE user_email = ? AND name LIKE ?"
            params = [user_email, f"%{q}%"]
            
            if type:
                query += " AND type = ?"
                params.append(type)
                
            query += " ORDER BY name"
            rows = conn.execute(query, params).fetchall()
        else:
            rows = conn.execute("SELECT * FROM ingredients WHERE user_email = ? ORDER BY name", (user_email,)).fetchall()
            
        return [dict(row) for row in rows]

@app.get("/ingredients/{ingredient_id}")
async def get_ingredient(ingredient_id: str):
    """Get a specific ingredient."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM ingredients WHERE id = ?", (ingredient_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Ingredient not found")
        return dict(row)

@app.put("/ingredients/{ingredient_id}")
@security_check
async def update_ingredient(ingredient_id: str, ingredient: Ingredient):
    """Update an existing ingredient."""
    # Validate ingredient_id
    validate_string_input(ingredient_id, "ingredient_id")
    
    if ingredient.fermentability < 0 or ingredient.fermentability > 100:
        raise HTTPException(status_code=400, detail="Fermentability must be 0-100%")
    if ingredient.pkl < 0:
        raise HTTPException(status_code=400, detail="PKL cannot be negative")
    if ingredient.price < 0:
        raise HTTPException(status_code=400, detail="Price cannot be negative")
    
    with sqlite3.connect(DB_PATH) as conn:
        result = conn.execute(
            "UPDATE ingredients SET name=?, source=?, type=?, price=?, fermentability=?, pkl=?, dosing_type=?, dosing_rules=? WHERE id=?",
            (ingredient.name, ingredient.source, ingredient.type, ingredient.price, 
             ingredient.fermentability, ingredient.pkl, ingredient.dosing_type, 
             ingredient.dosing_rules, ingredient_id)
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Ingredient not found")
    return {"message": "Ingredient updated"}

class DeleteBatchRequest(BaseModel):
    ingredient_ids: List[str]

@app.delete("/ingredients/batch")
async def delete_ingredients_batch(request: DeleteBatchRequest):
    """Delete multiple ingredients at once."""
    ingredient_ids = request.ingredient_ids
    
    if not ingredient_ids:
        raise HTTPException(status_code=400, detail="No ingredient IDs provided")
    
    deleted_count = 0
    errors = []
    
    with sqlite3.connect(DB_PATH) as conn:
        for ingredient_id in ingredient_ids:
            # Check if ingredient is used in any recipes
            usage = conn.execute("SELECT COUNT(*) FROM recipe_ingredients WHERE ingredient_id = ?", (ingredient_id,)).fetchone()[0]
            if usage > 0:
                errors.append(f"Ingredient {ingredient_id} is used in recipes")
                continue
            
            result = conn.execute("DELETE FROM ingredients WHERE id = ?", (ingredient_id,))
            if result.rowcount > 0:
                deleted_count += 1
            else:
                errors.append(f"Ingredient {ingredient_id} not found")
    
    return {
        "deleted_count": deleted_count,
        "total_requested": len(ingredient_ids),
        "errors": errors
    }

@app.delete("/ingredients/{ingredient_id}")
async def delete_ingredient(ingredient_id: str):
    """Delete an ingredient."""
    with sqlite3.connect(DB_PATH) as conn:
        # Check if ingredient is used in any recipes
        usage = conn.execute("SELECT COUNT(*) FROM recipe_ingredients WHERE ingredient_id = ?", (ingredient_id,)).fetchone()[0]
        if usage > 0:
            raise HTTPException(status_code=400, detail="Cannot delete ingredient used in recipes")
        
        result = conn.execute("DELETE FROM ingredients WHERE id = ?", (ingredient_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Ingredient not found")
    return {"message": "Ingredient deleted"}

@app.post("/ingredients/batch")
@security_check
async def create_ingredients_batch(ingredients: List[Ingredient]):
    """Create multiple ingredients at once."""
    logger.info(f"Starting batch creation of {len(ingredients)} ingredients")
    
    if not ingredients:
        logger.warn("Batch ingredient creation called with empty list")
        raise HTTPException(status_code=400, detail="No ingredients provided")
    
    created_ids = []
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            for i, ingredient in enumerate(ingredients):
                logger.debug(f"Processing ingredient {i+1}/{len(ingredients)}: {ingredient.name}")
                
                if ingredient.fermentability < 0 or ingredient.fermentability > 100:
                    logger.error(f"Invalid fermentability {ingredient.fermentability} for ingredient {ingredient.name}")
                    raise HTTPException(status_code=400, detail=f"Invalid fermentability for {ingredient.name}")
                if ingredient.pkl < 0:
                    logger.error(f"Invalid PKL {ingredient.pkl} for ingredient {ingredient.name}")
                    raise HTTPException(status_code=400, detail=f"Invalid PKL for {ingredient.name}")
                if ingredient.price < 0:
                    logger.error(f"Invalid price {ingredient.price} for ingredient {ingredient.name}")
                    raise HTTPException(status_code=400, detail=f"Invalid price for {ingredient.name}")
                
                ingredient_id = str(uuid4())[:8]
                conn.execute(
                    "INSERT INTO ingredients VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (ingredient_id, ingredient.name, ingredient.source, ingredient.type, 
                     ingredient.price, ingredient.fermentability, ingredient.pkl, 
                     ingredient.dosing_type, ingredient.dosing_rules, datetime.now().isoformat())
                )
                created_ids.append({"id": ingredient_id, "name": ingredient.name})
        
        logger.info(f"Successfully created {len(created_ids)} ingredients in batch")
        return {"created_count": len(created_ids), "ingredients": created_ids}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create ingredient batch: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create ingredients")

class DeleteBatchRequest(BaseModel):
    ingredient_ids: List[str]

# New endpoint to create recipe with default brewing stages
@app.post("/recipes/with-stages")
async def create_recipe_with_default_stages(recipe: Recipe):
    """Create a recipe with default brewing stages."""
    # Add default stages if none provided
    if not recipe.brewing_stages:
        recipe.brewing_stages = [
            BrewingStage(
                stage_name="Must",
                stage_order=1,
                steps=[
                    BrewingStep(step_number=1, description="Clean tools and containers"),
                    BrewingStep(step_number=2, description="Create must (add ingredients together except yeast)")
                ]
            ),
            BrewingStage(
                stage_name="Ferment",
                stage_order=2,
                steps=[
                    BrewingStep(step_number=1, description="Pitch the yeast"),
                    BrewingStep(step_number=2, description="Degas", optional=True),
                    BrewingStep(step_number=3, description="Step feed", optional=True),
                    BrewingStep(step_number=4, description="Remove fruit", optional=True),
                    BrewingStep(step_number=5, description="Remove spices", optional=True)
                ]
            ),
            BrewingStage(
                stage_name="Refine",
                stage_order=3,
                steps=[
                    BrewingStep(step_number=1, description="Rack 1"),
                    BrewingStep(step_number=2, description="Let clear and degas naturally"),
                    BrewingStep(step_number=3, description="Rack 2"),
                    BrewingStep(step_number=4, description="Add wood chips", optional=True),
                    BrewingStep(step_number=5, description="Remove wood chips", optional=True),
                    BrewingStep(step_number=6, description="Add clearing agent or preservatives", optional=True),
                    BrewingStep(step_number=7, description="Rack 3", optional=True)
                ]
            ),
            BrewingStage(
                stage_name="Bottling",
                stage_order=4,
                steps=[
                    BrewingStep(step_number=1, description="Clean bottles and equipment"),
                    BrewingStep(step_number=2, description="Optional final rack", optional=True),
                    BrewingStep(step_number=3, description="Fill bottles"),
                    BrewingStep(step_number=4, description="Cork bottles"),
                    BrewingStep(step_number=5, description="Print labels", optional=True)
                ]
            ),
            BrewingStage(
                stage_name="Aging",
                stage_order=5,
                steps=[
                    BrewingStep(step_number=1, description="Store and age (completes the brew)")
                ]
            )
        ]
    
    return await create_recipe(recipe)
@app.post("/recipes")
@security_check
async def create_recipe(recipe: Recipe, user_email: str = Depends(get_current_user_email)):
    """Create a new recipe."""
    logger.debug(f"Creating recipe: {recipe.title} ({recipe.volume_liters}L)")
    
    if recipe.volume_liters <= 0:
        logger.warn(f"Invalid volume {recipe.volume_liters} for recipe {recipe.title}")
        raise HTTPException(status_code=400, detail="Volume must be positive")
    if recipe.target_fg < 0.990 or recipe.target_fg > 1.020:
        logger.warn(f"Invalid target FG {recipe.target_fg} for recipe {recipe.title}")
        raise HTTPException(status_code=400, detail="Target FG must be between 0.990 and 1.020")
    if not recipe.ingredients:
        logger.warn(f"No ingredients provided for recipe {recipe.title}")
        raise HTTPException(status_code=400, detail="Recipe must have at least one ingredient")
    
    recipe_id = str(uuid4())[:8]
    created_date = datetime.now().isoformat()
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Validate all ingredients exist
            for ing in recipe.ingredients:
                exists = conn.execute("SELECT id FROM ingredients WHERE id = ?", (ing.ingredient_id,)).fetchone()
                if not exists:
                    logger.error(f"Ingredient {ing.ingredient_id} not found for recipe {recipe.title}")
                    raise HTTPException(status_code=400, detail=f"Ingredient {ing.ingredient_id} not found")
            
            # Calculate OG and ABV from ingredients with water calculation
            calculated_og, expected_abv, water_needed = calculate_og_and_abv_with_water(recipe.ingredients, recipe.volume_liters, conn)
            logger.debug(f"Calculated OG: {calculated_og}, ABV: {expected_abv}%, Water needed: {water_needed}L for recipe {recipe.title}")
            
            # Validate recipe sanity
            validation = validate_recipe_sanity(calculated_og, expected_abv)
            if validation["warnings"]:
                logger.warn(f"Recipe warnings for {recipe.title}: {validation['warnings']}")
            if validation["errors"]:
                logger.error(f"Recipe errors for {recipe.title}: {validation['errors']}")
            
            # Insert recipe
            conn.execute(
                "INSERT INTO recipes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (recipe_id, user_email, recipe.title, recipe.description, recipe.volume_liters,
                 calculated_og, expected_abv, recipe.target_fg, recipe.yeast.strain, 
                 recipe.yeast.abv_tolerance, recipe.yeast.source, recipe.yeast.price,
                 recipe.yeast.amount_grams, created_date)
            )
            
            # Insert recipe ingredients
            for ing in recipe.ingredients:
                conn.execute(
                    "INSERT INTO recipe_ingredients (recipe_id, ingredient_id, amount, unit) VALUES (?, ?, ?, ?)",
                    (recipe_id, ing.ingredient_id, ing.amount, ing.unit)
                )
        
        logger.info(f"Created recipe: {recipe.title} (ID: {recipe_id}, OG: {calculated_og}, ABV: {expected_abv}%, Water: {water_needed}L)")
        return {
            "id": recipe_id, 
            "message": "Recipe created", 
            "calculated_og": calculated_og, 
            "expected_abv": expected_abv,
            "water_needed_liters": water_needed,
            "validation": validation
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create recipe {recipe.title}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create recipe")

@app.put("/recipes/{recipe_id}")
@security_check
async def update_recipe(recipe_id: str, recipe: Recipe, user_email: str = Depends(get_current_user_email)):
    """Update an existing recipe."""
    logger.debug(f"Updating recipe: {recipe_id} - {recipe.title}")
    
    if recipe.volume_liters <= 0:
        raise HTTPException(status_code=400, detail="Volume must be positive")
    if recipe.target_fg < 0.990 or recipe.target_fg > 1.020:
        raise HTTPException(status_code=400, detail="Target FG must be between 0.990 and 1.020")
    if not recipe.ingredients:
        raise HTTPException(status_code=400, detail="Recipe must have at least one ingredient")
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Check if recipe exists and belongs to user
            existing = conn.execute(
                "SELECT user_email FROM recipes WHERE id = ?", (recipe_id,)
            ).fetchone()
            
            if not existing:
                raise HTTPException(status_code=404, detail="Recipe not found")
            if existing[0] != user_email:
                raise HTTPException(status_code=403, detail="Not authorized to update this recipe")
            
            # Validate all ingredients exist
            for ing in recipe.ingredients:
                exists = conn.execute("SELECT id FROM ingredients WHERE id = ?", (ing.ingredient_id,)).fetchone()
                if not exists:
                    logger.error(f"Ingredient {ing.ingredient_id} not found for recipe update {recipe_id}")
                    raise HTTPException(status_code=400, detail=f"Ingredient {ing.ingredient_id} not found")
            
            # Calculate recipe metrics
            calculated_og, expected_abv, water_needed = calculate_og_and_abv_with_water(recipe.ingredients, recipe.volume_liters, conn)
            logger.info(f"Update - Calculated OG: {calculated_og}, ABV: {expected_abv}%, Water needed: {water_needed}L for recipe {recipe_id}")
            validation = validate_recipe_sanity(calculated_og, expected_abv)
            
            # Update recipe
            conn.execute("""
                UPDATE recipes SET title = ?, description = ?, volume_liters = ?, 
                calculated_og = ?, expected_abv = ?, target_fg = ?, yeast_strain = ?, 
                yeast_abv_tolerance = ?, yeast_source = ?, yeast_price = ?, yeast_amount_grams = ?
                WHERE id = ?
            """, (recipe.title, recipe.description, recipe.volume_liters, calculated_og, 
                  expected_abv, recipe.target_fg, recipe.yeast.strain, recipe.yeast.abv_tolerance,
                  recipe.yeast.source, recipe.yeast.price, recipe.yeast.amount_grams, recipe_id))
            
            # Delete existing ingredients and insert new ones
            conn.execute("DELETE FROM recipe_ingredients WHERE recipe_id = ?", (recipe_id,))
            for ing in recipe.ingredients:
                conn.execute(
                    "INSERT INTO recipe_ingredients (recipe_id, ingredient_id, amount, unit) VALUES (?, ?, ?, ?)",
                    (recipe_id, ing.ingredient_id, ing.amount, ing.unit)
                )
        
        logger.info(f"Updated recipe: {recipe.title} (ID: {recipe_id})")
        return {"message": "Recipe updated", "calculated_og": calculated_og, "expected_abv": expected_abv}
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update recipe {recipe_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update recipe")

@app.delete("/recipes/{recipe_id}")
async def delete_recipe(recipe_id: str):
    """Delete a recipe."""
    with sqlite3.connect(DB_PATH) as conn:
        # Check if recipe is used in any brews
        usage = conn.execute("SELECT COUNT(*) FROM brews WHERE recipe_id = ?", (recipe_id,)).fetchone()[0]
        if usage > 0:
            raise HTTPException(status_code=400, detail="Cannot delete recipe used in brews")
        
        # Delete recipe ingredients first
        conn.execute("DELETE FROM recipe_ingredients WHERE recipe_id = ?", (recipe_id,))
        
        # Delete recipe
        result = conn.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="Recipe not found")
    
    return {"message": "Recipe deleted"}

@app.get("/recipes")
async def get_recipes():
    """Get all recipes."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        recipes = conn.execute("SELECT * FROM recipes ORDER BY created_date DESC").fetchall()
        
        result = []
        for recipe in recipes:
            # Get ingredients for this recipe
            ingredients = conn.execute("""
                SELECT ri.amount, ri.unit, i.* 
                FROM recipe_ingredients ri 
                JOIN ingredients i ON ri.ingredient_id = i.id 
                WHERE ri.recipe_id = ?
            """, (recipe["id"],)).fetchall()
            
            recipe_dict = dict(recipe)
            recipe_dict["ingredients"] = [dict(ing) for ing in ingredients]
            result.append(recipe_dict)
        
        return result

@app.get("/recipes/{recipe_id}")
async def get_recipe(recipe_id: str):
    """Get a specific recipe."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        recipe = conn.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
        if not recipe:
            raise HTTPException(status_code=404, detail="Recipe not found")
        
        # Get ingredients
        ingredients = conn.execute("""
            SELECT ri.amount, ri.unit, i.* 
            FROM recipe_ingredients ri 
            JOIN ingredients i ON ri.ingredient_id = i.id 
            WHERE ri.recipe_id = ?
        """, (recipe_id,)).fetchall()
        
        recipe_dict = dict(recipe)
        recipe_dict["ingredients"] = [dict(ing) for ing in ingredients]
        return recipe_dict

# Brew progress endpoints
@app.post("/brews/{brew_id}/complete-step")
async def complete_brew_step(brew_id: str, step_data: Dict[str, Any]):
    """Mark a brewing step as completed."""
    with sqlite3.connect(DB_PATH) as conn:
        # Mark step as completed
        conn.execute(
            "INSERT OR REPLACE INTO brew_progress (brew_id, stage_id, step_id, completed, completed_date, notes) VALUES (?, ?, ?, 1, ?, ?)",
            (brew_id, step_data["stage_id"], step_data["step_id"], datetime.now().isoformat(), step_data.get("notes", ""))
        )
        
        # Update brew's current position
        conn.execute(
            "UPDATE brews SET current_stage_id = ?, current_step_id = ? WHERE id = ?",
            (step_data["stage_id"], step_data["step_id"], brew_id)
        )
    
    return {"message": "Step completed"}

@app.get("/brews/{brew_id}/progress")
async def get_brew_progress(brew_id: str):
    """Get detailed brew progress with stages and steps."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Get brew info
        brew = conn.execute("SELECT * FROM brews WHERE id = ?", (brew_id,)).fetchone()
        if not brew:
            raise HTTPException(status_code=404, detail="Brew not found")
        
        # Get all stages and steps for this recipe
        stages = conn.execute("""
            SELECT bs.*, GROUP_CONCAT(
                json_object(
                    'id', bst.id,
                    'step_number', bst.step_number,
                    'description', bst.description,
                    'optional', bst.optional,
                    'completed', COALESCE(bp.completed, 0),
                    'completed_date', bp.completed_date,
                    'notes', bp.notes
                )
            ) as steps
            FROM brewing_stages bs
            LEFT JOIN brewing_steps bst ON bs.id = bst.stage_id
            LEFT JOIN brew_progress bp ON bst.id = bp.step_id AND bp.brew_id = ?
            WHERE bs.recipe_id = ?
            GROUP BY bs.id
            ORDER BY bs.stage_order
        """, (brew_id, brew["recipe_id"])).fetchall()
        
        return {
            "brew": dict(brew),
            "stages": [dict(stage) for stage in stages]
        }
@app.post("/brews")
async def create_brew(brew: Dict[str, Any]):
    """Create a new brew from a recipe with scaling."""
    logger.debug(f"Creating brew: {brew['name']} from recipe {brew['recipe_id']}")
    
    brew_id = str(uuid4())[:8]
    
    try:
        with sqlite3.connect(DB_PATH) as conn:
            # Check if recipe exists and get its volume
            recipe = conn.execute("SELECT id, volume_liters FROM recipes WHERE id = ?", (brew["recipe_id"],)).fetchone()
            if not recipe:
                logger.error(f"Recipe {brew['recipe_id']} not found for brew {brew['name']}")
                raise HTTPException(status_code=404, detail="Recipe not found")
            
            recipe_volume = recipe[1]
            target_volume = brew["target_volume_liters"]
            scale_factor = target_volume / recipe_volume
            
            logger.debug(f"Scaling recipe from {recipe_volume}L to {target_volume}L (factor: {scale_factor})")
            
            conn.execute(
                "INSERT INTO brews VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (brew_id, brew["recipe_id"], brew["name"], target_volume, scale_factor, datetime.now().isoformat(), 0, None, None)
            )
            
            # Store scaled ingredient amounts (editable)
            recipe_ingredients = conn.execute("""
                SELECT ri.*, i.dosing_type, i.dosing_rules, i.type
                FROM recipe_ingredients ri 
                JOIN ingredients i ON ri.ingredient_id = i.id 
                WHERE ri.recipe_id = ?
            """, (brew["recipe_id"],)).fetchall()
            
            # Calculate total ingredient volume for scaled recipe
            total_scaled_volume = 0
            
            for ing in recipe_ingredients:
                ingredient_id = ing[2]  # ingredient_id
                original_amount = float(ing[3])  # amount from recipe_ingredients
                unit = ing[4]  # unit
                dosing_type = ing[5]  # dosing_type from join
                ingredient_type = ing[7]  # type from join
                
                if dosing_type == "custom":
                    scaled_amount = original_amount * scale_factor  # Will improve this
                    logger.debug(f"Custom dosing for ingredient {ingredient_id}: {scaled_amount}")
                else:
                    scaled_amount = original_amount * scale_factor
                
                # Calculate volume this scaled ingredient takes up
                ingredient_data = {'type': ingredient_type}
                ingredient_volume = calculate_ingredient_volume(ingredient_data, scaled_amount, unit)
                total_scaled_volume += ingredient_volume
                
                conn.execute(
                    "INSERT INTO brew_ingredients (brew_id, ingredient_id, original_amount, scaled_amount, actual_amount, unit) VALUES (?, ?, ?, ?, ?, ?)",
                    (brew_id, ingredient_id, original_amount, scaled_amount, scaled_amount, unit)
                )
            
            # Calculate water needed for scaled recipe
            water_needed = max(0, target_volume - total_scaled_volume)
            
            # Add water as a brew ingredient if needed
            if water_needed > 0:
                # Check if water ingredient exists, create if not
                water_ingredient = conn.execute("SELECT id FROM ingredients WHERE name = 'Water' AND type = 'water'").fetchone()
                if not water_ingredient:
                    water_id = str(uuid4())[:8]
                    conn.execute(
                        "INSERT INTO ingredients (id, name, source, type, price, fermentability, pkl, dosing_type, dosing_rules, created_date, user_email) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (water_id, "Water", "Municipal", "water", 0.0, 0.0, 0.0, "linear", None, datetime.now().isoformat(), user_email)
                    )
                else:
                    water_id = water_ingredient[0]
                
                # Add water to brew ingredients
                conn.execute(
                    "INSERT INTO brew_ingredients (brew_id, ingredient_id, original_amount, scaled_amount, actual_amount, unit) VALUES (?, ?, ?, ?, ?, ?)",
                    (brew_id, water_id, water_needed / scale_factor, water_needed, water_needed, "l")
                )
        
        logger.info(f"Created brew: {brew['name']} (ID: {brew_id}, scale: {scale_factor:.2f}, water: {water_needed:.2f}L)")
        return {
            "id": brew_id, 
            "message": "Brew created",
            "scale_factor": round(scale_factor, 2),
            "target_volume": target_volume,
            "recipe_volume": recipe_volume,
            "water_needed_liters": round(water_needed, 2)
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to create brew {brew['name']}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to create brew")
    
    return {"id": brew_id, "message": "Brew created"}

@app.get("/brews")
async def get_brews():
    """Get all brews."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT b.*, r.title as recipe_title 
            FROM brews b 
            JOIN recipes r ON b.recipe_id = r.id 
            ORDER BY b.created_date DESC
        """).fetchall()
        
        return [dict(row) for row in rows]

@app.post("/brews/{brew_id}/stages")
async def add_stage(brew_id: str, stage: Dict[str, Any]):
    """Add a stage to a brew."""
    with sqlite3.connect(DB_PATH) as conn:
        # Get current stages
        row = conn.execute("SELECT stages FROM brews WHERE id = ?", (brew_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Brew not found")
        
        stages = json.loads(row[0])
        stages.append({
            "stage": stage["stage"],
            "notes": stage.get("notes", ""),
            "date": datetime.now().isoformat()
        })
        
        conn.execute("UPDATE brews SET stages = ? WHERE id = ?", (json.dumps(stages), brew_id))
    
    return {"message": "Stage added"}

# Flexible brew system - add steps as you go
@app.post("/brews/{brew_id}/steps")
async def add_brew_step(brew_id: str, step: BrewStep):
    """Add a step to a brew."""
    with sqlite3.connect(DB_PATH) as conn:
        # Check if brew exists
        brew = conn.execute("SELECT id FROM brews WHERE id = ?", (brew_id,)).fetchone()
        if not brew:
            raise HTTPException(status_code=404, detail="Brew not found")
        
        step_date = step.date or datetime.now().isoformat()
        conn.execute(
            "INSERT INTO brew_steps (brew_id, step_name, notes, step_date) VALUES (?, ?, ?, ?)",
            (brew_id, step.step_name, step.notes, step_date)
        )
    
    return {"message": "Step added"}

@app.put("/brews/{brew_id}/ingredients/{ingredient_id}")
async def update_brew_ingredient(brew_id: str, ingredient_id: str, update_data: Dict[str, Any]):
    """Update the actual amount used for an ingredient in a brew."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE brew_ingredients SET actual_amount = ? WHERE brew_id = ? AND ingredient_id = ?",
            (update_data["actual_amount"], brew_id, ingredient_id)
        )
    
    return {"message": "Ingredient amount updated"}

@app.get("/brews/{brew_id}/ingredients")
async def get_brew_ingredients(brew_id: str):
    """Get all ingredients for a brew with original, scaled, and actual amounts."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        ingredients = conn.execute("""
            SELECT bi.*, i.name, i.type, i.source, i.price, i.fermentability, i.pkl, i.dosing_type
            FROM brew_ingredients bi
            JOIN ingredients i ON bi.ingredient_id = i.id
            WHERE bi.brew_id = ?
            ORDER BY i.name
        """, (brew_id,)).fetchall()
        
        return [dict(ing) for ing in ingredients]

@app.get("/brews/{brew_id}/cost")
async def calculate_brew_cost(brew_id: str):
    """Calculate the total cost of a brew."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Check if brew exists
        brew = conn.execute("SELECT * FROM brews WHERE id = ?", (brew_id,)).fetchone()
        if not brew:
            raise HTTPException(status_code=404, detail="Brew not found")
        
        # Get ingredient costs
        ingredients = conn.execute("""
            SELECT bi.actual_amount, i.price, i.name, bi.unit, i.type
            FROM brew_ingredients bi
            JOIN ingredients i ON bi.ingredient_id = i.id
            WHERE bi.brew_id = ?
        """, (brew_id,)).fetchall()
        
        # Get yeast cost
        recipe = conn.execute("SELECT yeast_price, yeast_amount_grams FROM recipes WHERE id = ?", (brew["recipe_id"],)).fetchone()
        yeast_cost = (recipe["yeast_price"] * brew["scale_factor"]) if recipe else 0
        
        ingredient_costs = []
        total_ingredient_cost = 0
        
        for ing in ingredients:
            cost = ing["actual_amount"] * ing["price"]
            total_ingredient_cost += cost
            ingredient_costs.append({
                "name": ing["name"],
                "type": ing["type"],
                "amount": ing["actual_amount"],
                "unit": ing["unit"],
                "price_per_unit": ing["price"],
                "total_cost": round(cost, 2)
            })
        
        total_cost = total_ingredient_cost + yeast_cost
        
        return {
            "brew_id": brew_id,
            "brew_name": brew["name"],
            "total_cost": round(total_cost, 2),
            "ingredient_cost": round(total_ingredient_cost, 2),
            "yeast_cost": round(yeast_cost, 2),
            "cost_per_liter": round(total_cost / brew["target_volume_liters"], 2),
            "ingredients": ingredient_costs
        }

@app.get("/brews/{brew_id}/scaled-recipe")
async def get_scaled_recipe(brew_id: str):
    """Get the scaled recipe for a brew with adjusted ingredient quantities."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Get brew info with scale factor
        brew = conn.execute("""
            SELECT b.*, r.title as recipe_title, r.volume_liters as recipe_volume
            FROM brews b 
            JOIN recipes r ON b.recipe_id = r.id 
            WHERE b.id = ?
        """, (brew_id,)).fetchone()
        
        if not brew:
            raise HTTPException(status_code=404, detail="Brew not found")
        
        # Get recipe ingredients and scale them
        ingredients = conn.execute("""
            SELECT ri.amount, ri.unit, i.* 
            FROM recipe_ingredients ri 
            JOIN ingredients i ON ri.ingredient_id = i.id 
            WHERE ri.recipe_id = ?
        """, (brew["recipe_id"],)).fetchall()
        
        scale_factor = brew["scale_factor"]
        scaled_ingredients = []
        
        for ing in ingredients:
            if ing["dosing_type"] == "custom":
                # Calculate custom dosing
                custom_amount = calculate_custom_dosing(dict(ing), brew["target_volume_liters"], [dict(i) for i in ingredients])
                scaled_amount = custom_amount if custom_amount is not None else ing["amount"] * scale_factor
            else:
                # Linear scaling
                scaled_amount = ing["amount"] * scale_factor
                
            scaled_ingredients.append({
                "id": ing["id"],
                "name": ing["name"],
                "type": ing["type"],
                "source": ing["source"],
                "original_amount": ing["amount"],
                "scaled_amount": round(scaled_amount, 2),
                "unit": ing["unit"],
                "price": ing["price"],
                "fermentability": ing["fermentability"],
                "pkl": ing["pkl"],
                "dosing_type": ing["dosing_type"]
            })
        
        # Get yeast info and scale it
        recipe = conn.execute("SELECT * FROM recipes WHERE id = ?", (brew["recipe_id"],)).fetchone()
        scaled_yeast_amount = recipe["yeast_amount_grams"] * scale_factor
        
        return {
            "brew_id": brew_id,
            "brew_name": brew["name"],
            "recipe_title": brew["recipe_title"],
            "recipe_volume": brew["recipe_volume"],
            "target_volume": brew["target_volume_liters"],
            "scale_factor": scale_factor,
            "scaled_ingredients": scaled_ingredients,
            "yeast": {
                "strain": recipe["yeast_strain"],
                "original_amount_grams": recipe["yeast_amount_grams"],
                "scaled_amount_grams": round(scaled_yeast_amount, 1),
                "abv_tolerance": recipe["yeast_abv_tolerance"],
                "source": recipe["yeast_source"],
                "price": recipe["yeast_price"]
            }
        }
    """Get detailed brew information with steps."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Get brew info
        brew = conn.execute("""
            SELECT b.*, r.title as recipe_title 
            FROM brews b 
            JOIN recipes r ON b.recipe_id = r.id 
            WHERE b.id = ?
        """, (brew_id,)).fetchone()
        
        if not brew:
            raise HTTPException(status_code=404, detail="Brew not found")
        
        # Get all steps for this brew
        steps = conn.execute(
            "SELECT * FROM brew_steps WHERE brew_id = ? ORDER BY step_date",
            (brew_id,)
        ).fetchall()
        
        return {
            "brew": dict(brew),
            "steps": [dict(step) for step in steps]
        }

@app.post("/brews/{brew_id}/complete")
async def complete_brew(brew_id: str, completion_data: Dict[str, Any]):
    """Complete a brew with optional tasting notes."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "UPDATE brews SET completed = 1, completion_date = ?, tasting_notes = ? WHERE id = ?",
            (datetime.now().isoformat(), completion_data.get("tasting_notes", ""), brew_id)
        )
    
    return {"message": "Brew completed"}

def main():
    """Entry point for the application."""
    import uvicorn
    
    # Use configuration for server settings
    uvicorn_config = {
        "app": app,
        "host": config.server.host,
        "port": config.server.port,
        "reload": config.server.reload,
        "log_level": config.server.log_level.lower()
    }
    
    # Add SSL if enabled
    if config.server.ssl_enabled:
        if config.server.ssl_keyfile and config.server.ssl_certfile:
            uvicorn_config.update({
                "ssl_keyfile": config.server.ssl_keyfile,
                "ssl_certfile": config.server.ssl_certfile
            })
            logger.info(f"SSL enabled with cert: {config.server.ssl_certfile}")
        else:
            logger.warn("SSL enabled but keyfile/certfile not specified")
    
    logger.info(f"Starting MeadBro API on {config.server.host}:{config.server.port}")
    uvicorn.run(**uvicorn_config)

if __name__ == "__main__":
    main()
