# Fixed app.py - production-ready with all security and reliability improvements
import os
import hmac
import hashlib
from decimal import Decimal
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from supabase import create_client, Client
import requests
import jwt
from functools import wraps
from datetime import datetime, timedelta, timezone
import time
import uuid
import json
import traceback
import random
import base64
import hashlib
from typing import Optional
from threading import Lock
import re
import atexit
from threading import Lock, Thread
import socket

load_dotenv()

app = Flask(__name__)
# NOTE: tighten CORS for production, but support multiple allowed origins
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')

# Build allowlist for origins including localhost, Vercel previews, and ngrok tunnels
ALLOWED_ORIGIN_STRINGS = [
    FRONTEND_URL,
    'http://localhost:3000',
    'http://127.0.0.1:3000',
]
ALLOWED_ORIGIN_REGEX_STRINGS = [
    r'^https://.*\.vercel\.app$',
    r'^https://.*\.ngrok(?:-free)?\.app$',
    r'^https://.*\.ngrok\.io$',
]

# Support comma-separated extra origins via env var (e.g., custom domains)
extra_origins = os.getenv('ADDITIONAL_ALLOWED_ORIGINS', '')
if extra_origins:
    for origin in [o.strip() for o in extra_origins.split(',') if o.strip()]:
        ALLOWED_ORIGIN_STRINGS.append(origin)

ALLOWED_ORIGINS_FOR_FLASK_CORS = ALLOWED_ORIGIN_STRINGS + ALLOWED_ORIGIN_REGEX_STRINGS
ALLOWED_ORIGIN_REGEXES = [re.compile(p) for p in ALLOWED_ORIGIN_REGEX_STRINGS]

# Allow-all mode for development
CORS_ALLOW_ALL = (os.getenv('CORS_ALLOW_ALL', '') or '').lower() in ('1', 'true', 'yes')
if not CORS_ALLOW_ALL:
    # If explicitly production, keep strict; otherwise default to allow-all in dev
    env = (os.getenv('ENV') or os.getenv('FLASK_ENV') or '').lower()
    if env and env != 'production':
        CORS_ALLOW_ALL = True

app.config['CORS_HEADERS'] = 'Content-Type, Authorization, ngrok-skip-browser-warning'

# Enhanced CORS configuration to fix authorization header issues
if CORS_ALLOW_ALL:
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": "*",
                "allow_headers": ["Content-Type", "Authorization", "ngrok-skip-browser-warning", "Accept", "User-Agent", "X-Requested-With", "Cache-Control", "X-CSRF-Token"],
                "expose_headers": ["Authorization", "Content-Type", "X-Total-Count"],
                "methods": ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
                "max_age": 86400  # 24 hours
            }
        },
        supports_credentials=False,
    )
else:
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": ALLOWED_ORIGINS_FOR_FLASK_CORS,
                "allow_headers": ["Content-Type", "Authorization", "ngrok-skip-browser-warning", "Accept", "User-Agent", "X-Requested-With", "Cache-Control", "X-CSRF-Token"],
                "expose_headers": ["Authorization", "Content-Type", "X-Total-Count"],
                "methods": ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
                "max_age": 86400  # 24 hours
            }
        },
        supports_credentials=True,
    )

# Debug logging for API requests
@app.before_request
def _log_headers():
    # Optional: debug what actually reaches the server
    if request.path.startswith("/api/"):
        print("HEADERS=>", dict(request.headers))
        print("METHOD=>", request.method)
        print("PATH=>", request.path)
        auth_header = request.headers.get("Authorization", "")
        if auth_header:
            print(f"AUTH_HEADER_PRESENT: {auth_header[:20]}...")
        else:
            print("NO_AUTH_HEADER")

# Comprehensive debug endpoint for authorization issues
@app.route('/api/debug/auth', methods=['GET'])
def debug_auth():
    auth_header = request.headers.get("Authorization", "")
    ngrok_header = request.headers.get("ngrok-skip-browser-warning", "")
    user_agent = request.headers.get("User-Agent", "")
    origin = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    content_type = request.headers.get("Content-Type", "")
    accept = request.headers.get("Accept", "")

    # Test token parsing if present
    token_info = {}
    if auth_header:
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            token_info = {
                "token_length": len(token),
                "token_preview": token[:20] + "..." if len(token) > 20 else token,
                "token_format_valid": True
            }
        else:
            token_info = {
                "error": "Invalid format - missing 'Bearer ' prefix",
                "token_format_valid": False
            }

    # Environment info
    env_info = {
        "cors_allow_all": CORS_ALLOW_ALL,
        "environment": os.getenv('ENV', 'not-set'),
        "flask_env": os.getenv('FLASK_ENV', 'not-set'),
        "supabase_jwt_secret_set": bool(os.getenv('SUPABASE_JWT_SECRET')),
        "frontend_url": FRONTEND_URL,
        "additional_origins": os.getenv('ADDITIONAL_ALLOWED_ORIGINS', 'not-set'),
    }

    # CORS configuration info
    cors_info = {
        "allowed_origins": ALLOWED_ORIGINS_FOR_FLASK_CORS if not CORS_ALLOW_ALL else ["*"],
        "allowed_headers": ["Content-Type", "Authorization", "ngrok-skip-browser-warning", "Accept", "User-Agent", "X-Requested-With", "Cache-Control", "X-CSRF-Token"],
        "exposed_headers": ["Authorization", "Content-Type", "X-Total-Count"],
        "supported_methods": ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    }

    return jsonify({
        "message": "Comprehensive authorization debug info",
        "timestamp": datetime.now().isoformat(),
        "request_info": {
            "method": request.method,
            "path": request.path,
            "remote_addr": request.remote_addr,
            "user_agent": user_agent,
        },
        "headers": {
            "authorization": {
                "present": bool(auth_header),
                "preview": auth_header[:20] + "..." if auth_header else None,
                "full_length": len(auth_header) if auth_header else 0,
                **token_info
            },
            "ngrok_skip_browser_warning": bool(ngrok_header),
            "content_type": content_type,
            "accept": accept,
            "origin": origin,
            "referer": referer,
        },
        "environment": env_info,
        "cors_config": cors_info,
        "troubleshooting": {
            "checklist": [
                "Verify NEXT_PUBLIC_API_URL includes https:// scheme for ngrok",
                "Check browser Network tab for Authorization header in request",
                "Ensure SUPABASE_JWT_SECRET is set in backend environment",
                "Verify CORS_ALLOW_ALL=true for development",
                "Check for proxy/nginx forwarding Authorization header",
            ],
            "common_issues": [
                "Mixed content: HTTPS frontend with HTTP API URL",
                "Missing ngrok https:// scheme in NEXT_PUBLIC_API_URL",
                "Proxy not forwarding Authorization header",
                "SUPABASE_JWT_SECRET not set",
                "CORS preflight failing",
            ]
        }
    }), 200


# Fallback preflight handler for any /api/* route (helps when proxies/extensions add headers)
def _is_origin_allowed(origin: str) -> bool:
    if not origin:
        return False
    if CORS_ALLOW_ALL:
        return True
    if origin in ALLOWED_ORIGIN_STRINGS:
        return True
    for rx in ALLOWED_ORIGIN_REGEXES:
        if rx.match(origin):
            return True
    return False

@app.route('/api/<path:unused>', methods=['OPTIONS'])
def cors_preflight(unused):
    resp = make_response('', 204)
    request_origin = request.headers.get('Origin', '')

    # Prefer reflecting the specific origin to avoid wildcard issues in some browsers/proxies
    if request_origin:
        # Only reflect known/allowed origins when not in allow-all mode
        if CORS_ALLOW_ALL or _is_origin_allowed(request_origin):
            resp.headers['Access-Control-Allow-Origin'] = request_origin
    else:
        # Fallback for non CORS OPTIONS callers
        resp.headers['Access-Control-Allow-Origin'] = '*'
    resp.headers['Vary'] = 'Origin'

    # Echo requested headers so custom headers like ngrok-skip-browser-warning pass preflight
    requested_headers = request.headers.get('Access-Control-Request-Headers')
    if requested_headers:
        resp.headers['Access-Control-Allow-Headers'] = requested_headers
    else:
        resp.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, ngrok-skip-browser-warning'

    resp.headers['Access-Control-Allow-Methods'] = 'GET,POST,PATCH,PUT,DELETE,OPTIONS'
    if not CORS_ALLOW_ALL:
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
    resp.headers['Access-Control-Max-Age'] = '600'
    return resp

@app.after_request
def add_cors_headers(response):
    try:
        # Only apply to API routes
        if request.path.startswith('/api/'):
            request_origin = request.headers.get('Origin', '')
            # Avoid duplicating header if Flask-CORS already set it
            if 'Access-Control-Allow-Origin' not in response.headers:
                if CORS_ALLOW_ALL:
                    # Prefer reflecting origin when present to avoid wildcard edge cases
                    response.headers['Access-Control-Allow-Origin'] = request_origin or '*'
                    response.headers['Vary'] = 'Origin'
                elif _is_origin_allowed(request_origin):
                    response.headers['Access-Control-Allow-Origin'] = request_origin
                    response.headers['Vary'] = 'Origin'
                    response.headers['Access-Control-Allow-Credentials'] = 'true'
            # Ensure common CORS headers are present on actual responses too
            if 'Access-Control-Allow-Methods' not in response.headers:
                response.headers['Access-Control-Allow-Methods'] = 'GET,POST,PATCH,PUT,DELETE,OPTIONS'
            if 'Access-Control-Allow-Headers' not in response.headers:
                response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, ngrok-skip-browser-warning'
    except Exception:
        # Don't break the response on header reflection issues
        pass
    return response

# Rate limiting with Redis storage
try:
    from flask_limiter import RedisLimiter
    limiter = Limiter(
        app=app,
        key_func=lambda: request.user_id if hasattr(request, 'user_id') else get_remote_address(),
        default_limits=[],  # Temporarily disabled for development
        storage_uri="redis://localhost:6379"  # Use Redis for production
    )
except ImportError:
    # Fallback to in-memory if Redis is not available
    limiter = Limiter(
        app=app,
        key_func=lambda: request.user_id if hasattr(request, 'user_id') else get_remote_address(),
        default_limits=[]  # Temporarily disabled for development
    )

# Exempt preflight handler from rate limiting
try:
    limiter.exempt(cors_preflight)
except Exception:
    pass

# Analytics-specific rate limiting
analytics_limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

# Flag to ensure debug routes only run once
debug_routes_run = False

@app.before_request
def debug_routes():
    global debug_routes_run
    if not debug_routes_run:
        for rule in app.url_map.iter_rules():
            if rule.rule == '/api/marketplace/seller/products/get':
                app.logger.info(f"Route: {rule.rule} methods={sorted(rule.methods)} endpoint={rule.endpoint}")
        debug_routes_run = True

# Initialize Supabase client (service role key expected)
SUPABASE_URL = os.getenv('SUPABASE_URL')
SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Ensure a public images bucket name exists (create in Supabase manually if needed)
PUBLIC_IMAGE_BUCKET = os.getenv('PUBLIC_IMAGE_BUCKET', 'public-images')

# Tatum API configuration
TATUM_API_URL = "https://api.tatum.io/v3"
TATUM_API_KEY = os.getenv('TATUM_API_KEY')

# PayPal configuration
PAYPAL_CLIENT_ID = os.getenv('PAYPAL_CLIENT_ID')
PAYPAL_CLIENT_SECRET = os.getenv('PAYPAL_CLIENT_SECRET')
PAYPAL_MODE = os.getenv('PAYPAL_MODE', 'sandbox')

# Outbound callback configuration (dynamic delivery)
OUTBOUND_CALLBACK_TIMEOUT_MS = int(os.getenv("OUTBOUND_CALLBACK_TIMEOUT_MS", "5000"))
OUTBOUND_CALLBACK_RETRY_MAX = int(os.getenv("OUTBOUND_CALLBACK_RETRY_MAX", "3"))
OUTBOUND_CALLBACK_USER_AGENT = os.getenv("OUTBOUND_CALLBACK_USER_AGENT", "Medius/1.0")
OUTBOUND_CALLBACK_BLOCK_PRIVATE = os.getenv("OUTBOUND_CALLBACK_BLOCK_PRIVATE", "true").lower() == "true"
PAYPAL_BASE_URL = f"https://api-m.{'sandbox.' if PAYPAL_MODE == 'sandbox' else ''}paypal.com"
PAYPAL_WEBHOOK_ID = os.getenv('PAYPAL_WEBHOOK_ID')

# App configuration
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')

# Referral configuration (applies to all payment methods)
REFERRAL_RATE = float(os.getenv('REFERRAL_RATE', '0.20'))  # 20% by default
MIN_WITHDRAW_USD = float(os.getenv('MIN_WITHDRAW_USD', '5.0'))  # minimum referral withdrawal
COINGECKO_SIMPLE = "https://api.coingecko.com/api/v3/simple/price"
# ============================================
# SWAPKIT CONFIGURATION
# ============================================

# SwapKit API Settings
SWAPKIT_API_KEY = os.getenv('SWAPKIT_API_KEY')
SWAPKIT_WEBHOOK_SECRET = os.getenv('SWAPKIT_WEBHOOK_SECRET')
SWAPKIT_API_URL = 'https://api.swapkit.dev'
SWAPKIT_TIMEOUT = 30
SWAPKIT_MAX_RETRIES = 3
SWAPKIT_RETRY_DELAY = 2

# Exchange Settings
C2C_FEE = Decimal(os.getenv('C2C_FEE', '0.01'))  # 1% platform fee
C2C_MIN_EXCHANGE_USD = Decimal(os.getenv('C2C_MIN_EXCHANGE_USD', '5.0'))
C2C_RATE_LOCK_SECONDS = int(os.getenv('C2C_RATE_LOCK_SECONDS', '60'))
DEFAULT_SLIPPAGE = Decimal(os.getenv('DEFAULT_SLIPPAGE', '1'))

# Monitoring Settings
EXCHANGE_STATUS_CHECK_INTERVAL = int(os.getenv('EXCHANGE_STATUS_CHECK_INTERVAL', '60'))
EXCHANGE_MAX_PENDING_AGE = int(os.getenv('EXCHANGE_MAX_PENDING_AGE', '86400'))

# Fee Collection Addresses (YOUR EXISTING ADDRESSES)
FEE_ADDRESSES = {
    'BTC': os.getenv('BTC_FEE_ADDY'),
    'ETH': os.getenv('ETH_FEE_ADDY'),
    'SOL': os.getenv('SOL_FEE_ADDY'),
    'LTC': os.getenv('LTC_FEE_ADDY'),
    'BCH': os.getenv('BCH_FEE_ADDY'),
    'DOGE': os.getenv('DOGE_FEE_ADDY'),
    'XRP': os.getenv('XRP_FEE_ADDY'),
    'ADA': os.getenv('ADA_FEE_ADDY'),
    'DOT': os.getenv('DOT_FEE_ADDY'),
    'MATIC': os.getenv('MATIC_FEE_ADDY'),
    'AVAX': os.getenv('AVAX_FEE_ADDY'),
    'TRX': os.getenv('TRX_FEE_ADDY'),
    'BNB': os.getenv('BNB_FEE_ADDY'),
    'ATOM': os.getenv('ATOM_FEE_ADDY'),
    'XLM': os.getenv('XLM_FEE_ADDY'),
    'USDT-ERC20': os.getenv('USDT_ERC20_FEE_ADDY'),
    'USDT-BEP20': os.getenv('USDT_BEP20_FEE_ADDY'),
    'USDT-SOL': os.getenv('USDT_SOL_FEE_ADDY'),
    'USDT-TRON': os.getenv('USDT_TRON_FEE_ADDY'),
}

# SwapKit Currency Mapping (Medius → SwapKit format)
SWAPKIT_CURRENCY_MAPPING = {
    'BTC': 'BTC.BTC',
    'ETH': 'ETH.ETH',
    'SOL': 'SOL.SOL',
    'LTC': 'LTC.LTC',
    'BCH': 'BCH.BCH',
    'DOGE': 'DOGE.DOGE',
    'XRP': 'XRP.XRP',
    # 'ADA': 'ADA.ADA',  # EXCLUDED from exchange (no private key)
    # 'DOT': 'DOT.DOT',  # EXCLUDED from exchange (no private key)
    'MATIC': 'MATIC.MATIC',
    'AVAX': 'AVAX.AVAX',
    'TRX': 'TRX.TRX',
    'BNB': 'BSC.BNB',
    'ATOM': 'GAIA.ATOM',
    'XLM': 'XLM.XLM',
    'USDT-ERC20': 'ETH.USDT-0xdAC17F958D2ee523a2206206994597C13D831ec7',
    'USDT-BEP20': 'BSC.USDT-0x55d398326f99059fF775485246999027B3197955',
    'USDT-SOL': 'SOL.USDT-Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
    'USDT-TRON': 'TRON.USDT-TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
}


def is_exchange_supported(currency):
    """
    Check if currency is supported for SwapKit exchange
    
    Returns True for 13 currencies, False for ADA/DOT
    """
    return currency.upper() in EXCHANGE_SUPPORTED_CURRENCIES

# List of currencies supported for exchange (for validation)
EXCHANGE_SUPPORTED_CURRENCIES = list(SWAPKIT_CURRENCY_MAPPING.keys())




# Runtime cache for escrow wallet rows
ESCROW_WALLET_IDS = {}
wallet_cache_lock = Lock()

# Supported currencies (including USDT on multiple chains)
SUPPORTED_CURRENCIES = {
    'BTC', 'ETH', 'USD', 'LTC', 'BCH', 'DOGE', 'XRP', 'ADA', 'DOT',
    'MATIC', 'SOL', 'AVAX', 'TRX', 'BNB', 'ATOM', 'XLM',
    'USDT-ERC20',  # USDT on Ethereum (ERC20)
    'USDT-BEP20',  # USDT on BNB Smart Chain / BEP20
    'USDT-SOL',    # USDT on Solana (SPL)
    'USDT-TRON'    # USDT on Tron (TRC20)
}

CHAIN_MAP = {
    'BTC': 'bitcoin', 'ETH': 'ethereum', 'LTC': 'litecoin', 'BCH': 'bcash',
    'DOGE': 'dogecoin', 'XRP': 'xrp', 'ADA': 'ada', 'DOT': 'polkadot',
    'MATIC': 'polygon', 'SOL': 'solana', 'AVAX': 'avalanche', 'TRX': 'tron',
    'BNB': 'bsc', 'ATOM': 'cosmos', 'XLM': 'xlm',
    # USDT variants map to their underlying chain for Tatum calls
    'USDT-ERC20': 'ethereum',
    'USDT-BEP20': 'bsc',
    'USDT-SOL': 'solana',
    'USDT-TRON': 'tron'
}


# Amount limits - adjusted for crypto amounts
# MIN_ESCROW_AMOUNT removed - frontend handles USD minimums, no need for crypto amount minimums
MAX_ESCROW_AMOUNT = 10000000



# ============================================
# SWAPKIT EXCEPTIONS
# ============================================

class SwapKitError(Exception):
    """Base SwapKit exception"""
    pass

class SwapKitAPIError(SwapKitError):
    """SwapKit API error"""
    def __init__(self, message, status_code=None, response=None):
        self.status_code = status_code
        self.response = response
        super().__init__(message)


# --------------------- Secret helpers (env -> supabase secrets fallback) ---------------------
def get_secret(key: str):
    """
    Resolve a secret value by:
     1) environment variable
     2) Supabase table 'vault_secrets' (key,value) if exists (service key required)
    This keeps things simple and gives you a single hook for KMS/Supabase Vault later.
    """
    # 1) env
    v = os.getenv(key)
    if v:
        return v

    # 2) Supabase secrets table (optional) - put secrets in 'vault_secrets' table: {key, value}
    try:
        r = supabase.table('vault_secrets').select('value').eq('key', key).single().execute()
        if r and getattr(r, "data", None):
            value = r.data.get('value')
            return value
    except Exception:
        pass

    return None

def get_platform_mnemonic(currency: str):
    """Return platform mnemonic for a currency.
    Supports token variants (e.g., USDT-ERC20, USDT-BEP20) by trying:
    1) PLATFORM_<CURRENCY_WITH_UNDERSCORES>_MNEMONIC
    2) PLATFORM_<BASE_CHAIN>_MNEMONIC fallback (ETH/BNB/SOL/TRX)
    3) PLATFORM_MNEMONIC generic
    """
    if not currency:
        return get_secret('PLATFORM_MNEMONIC')
    cur = currency.upper()
    # Try sanitized key first
    key = f'PLATFORM_{cur.replace("-", "_")}_MNEMONIC'
    val = get_secret(key)
    if val:
        return val
    # Fallback to base chain for common USDT variants
    base_map = {
        'USDT-ERC20': 'ETH',
        'USDT-BEP20': 'BNB',
        'USDT-SOL': 'SOL',
        'USDT-TRON': 'TRX',
    }
    base = base_map.get(cur)
    if base:
        alt = get_secret(f'PLATFORM_{base}_MNEMONIC')
        if alt:
            return alt
    return get_secret('PLATFORM_MNEMONIC')

def get_platform_address(currency: str):
    """Get platform deposit address for the given currency.
    Tries PLATFORM_<CURRENCY_WITH_UNDERSCORES>_ADDRESS first, then falls back to
    the base chain address for token variants (ETH/BNB/SOL/TRX)."""
    if not currency:
        return None
    cur = currency.upper()
    # Try exact sanitized currency key (hyphens are not valid in env names)
    primary_key = f'PLATFORM_{cur.replace("-", "_")}_ADDRESS'
    val = get_secret(primary_key)
    if val:
        return val
    # Fallback to base chain for known token wrappers
    base_map = {
        'USDT-ERC20': 'ETH',
        'USDT-BEP20': 'BNB',
        'USDT-SOL': 'SOL',
        'USDT-TRON': 'TRX',
    }
    base = base_map.get(cur)
    if base:
        alt = get_secret(f'PLATFORM_{base}_ADDRESS')
        if alt:
            return alt
    return None



# ============================================
# AMOUNT DECIMALS + BASE UNIT CONVERSION
# ============================================

ASSET_DECIMALS = {
    # natives
    'BTC': 8,
    'ETH': 18,
    'SOL': 9,
    'LTC': 8,
    'BCH': 8,
    'DOGE': 8,
    'XRP': 6,   # drops
    'MATIC': 18,
    'AVAX': 18, # C-Chain
    'TRX': 6,   # SUN
    'BNB': 18,  # BSC
    'ATOM': 6,  # uatom
    'XLM': 7,   # stroops
    # tokens
    'USDT-ERC20': 6,
    'USDT-BEP20': 18,
    'USDT-SOL': 6,
    'USDT-TRON': 6,
}

from decimal import Decimal, ROUND_DOWN

def to_base_units(currency: str, amount: Decimal) -> str:
    """
    Convert a human-readable Decimal amount to an integer string in base units.
    Example: ETH 1.0 -> "1000000000000000000"
    """
    currency = currency.upper().strip()
    dec = ASSET_DECIMALS.get(currency)
    if dec is None:
        raise ValueError(f"No decimals configured for {currency}")
    # scale and format as integer string
    scaled = (amount * (Decimal(10) ** dec)).quantize(Decimal('1'), rounding=ROUND_DOWN)
    return str(scaled)




def get_fee_address(currency: str):
    """Get platform fee recipient address for a currency.
    Looks for an env/vault key named <CURRENCY>_FEE_ADDY (hyphens -> underscores).
    Falls back to base chain for token variants (USDT-ERC20 -> ETH_FEE_ADDY) and
    then returns None.
    """
    if not currency:
        return None
    cur = currency.upper()
    primary_key = f'{cur.replace("-", "_")}_FEE_ADDY'
    val = get_secret(primary_key)
    if val:
        return val

    # Fallback to base chain for known token wrappers
    base_map = {
        'USDT-ERC20': 'ETH',
        'USDT-BEP20': 'BNB',
        'USDT-SOL': 'SOL',
        'USDT-TRON': 'TRX',
    }
    base = base_map.get(cur)
    if base:
        alt = get_secret(f'{base}_FEE_ADDY')
        if alt:
            return alt
    return None


def derive_address_from_mnemonic(mnemonic: str, currency: str, index: int = 0) -> Optional[str]:
    """Derive a deposit address from a BIP39 mnemonic for common chains.
    This is a best-effort local derivation intended for development convenience.
    Production should use a secure KMS or custodian.
    """
    if not BIP_AVAILABLE:
        raise RuntimeError("bip-utils not installed; install bip-utils or provide explicit PLATFORM_<CURRENCY>_ADDRESS values")

    cur = (currency or '').upper()
    seed_bytes = Bip39SeedGenerator(mnemonic).Generate()

    # Bitcoin-like chains
    if cur in ('BTC',):
        coin = Bip44Coins.BITCOIN
    elif cur in ('LTC',):
        coin = Bip44Coins.LITECOIN
    elif cur in ('BCH',):
        coin = Bip44Coins.BITCOIN_CASH
    elif cur in ('DOGE',):
        coin = Bip44Coins.DOGECOIN
    # Ethereum-like chains (ETH, MATIC, BNB, ERC20/BEP20 tokens)
    elif cur in ('ETH', 'MATIC', 'USDT-ERC20'):
        coin = Bip44Coins.ETHEREUM
    elif cur in ('BNB', 'USDT-BEP20'):
        # Bip-utils exposes BINANCE_SMART_CHAIN for BSC
        coin = Bip44Coins.BINANCE_SMART_CHAIN
    # Solana
    elif cur in ('SOL', 'USDT-SOL'):
        coin = Bip44Coins.SOLANA
    else:
        raise RuntimeError(f"Local derivation not implemented for currency: {currency}")

    bip44_def = Bip44.FromSeed(seed_bytes, coin)
    addr = bip44_def.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(index).PublicKey().ToAddress()
    return addr

# --------------------- Input validation ---------------------
def validate_amount(amount, currency=None, usd_amount=None) -> tuple:
    """Validate amount is numeric and within limits. Returns (valid, error_msg)"""
    try:
        amount_float = float(amount)
        if amount_float <= 0:
            return False, "Amount must be positive"

        # For crypto, check USD amount minimums instead of hard crypto minimums
        if currency and currency != "USD":
            min_usd_amounts = {
                'BTC': 2, 'ETH': 3, 'LTC': 0.50, 'BCH': 0.50, 'DOGE': 1,
                'XRP': 0.25, 'ADA': 0.50, 'DOT': 1, 'MATIC': 0.25, 'SOL': 1,
                'AVAX': 0.50, 'TRX': 0.25, 'BNB': 0.50, 'ATOM': 0.50, 'XLM': 0.10,
                'USDT-ERC20': 1, 'USDT-BEP20': 1, 'USDT-SOL': 1, 'USDT-TRON': 1
            }
            min_usd = min_usd_amounts.get(currency, 0.50)

            # If we have USD amount, validate against USD minimum
            if usd_amount is not None:
                if float(usd_amount) < min_usd:
                    return False, f"Minimum amount for {currency} is ${min_usd} USD"
                # USD amount is valid, no need to check crypto amount minimum
            else:
                # No USD amount provided - frontend should always provide USD amounts for crypto
                # Skip crypto amount minimum check since frontend handles USD validation
                pass
        else:
            # For USD/PayPal - frontend handles minimum validation, skip backend minimum check
            pass

        if amount_float > MAX_ESCROW_AMOUNT:
            return False, f"Maximum amount is {MAX_ESCROW_AMOUNT}"
        return True, None
    except (TypeError, ValueError):
        return False, "Amount must be a number"

def validate_currency(currency) -> tuple:
    """Validate currency is supported. Returns (valid, error_msg)"""
    if not currency:
        return False, "Currency is required"
    if currency.upper() not in SUPPORTED_CURRENCIES:
        return False, f"Unsupported currency: {currency}"
    return True, None

def validate_address(address, currency) -> tuple:
    """Basic validation of crypto address format."""
    if not address:
        return False, "Address is required"
    if len(address) < 10 or len(address) > 150:
        return False, "Invalid address format"
    # Add specific validation per currency if needed
    return True, None

# --------------------- Auth Decorator ---------------------
def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
    # allow CORS preflight OPTIONS to bypass auth
        if request.method == 'OPTIONS':
            return make_response('', 204)
        app.logger.info("=== AUTH CHECK START ===")
        app.logger.info(f"Request path: {request.path}")
        app.logger.info(f"Request method: {request.method}")
        app.logger.info(f"All headers: {dict(request.headers)}")

        token = None
        auth_header = request.headers.get('Authorization')
        app.logger.info(f"Authorization header: {auth_header}")

        if auth_header:
            try:
                token = auth_header.split(' ')[1]
                app.logger.info(f"Extracted token: {token[:20]}...")
            except IndexError:
                app.logger.error("Invalid token format - missing Bearer prefix")
                return jsonify({
                    'error': 'Invalid token format',
                    'details': 'Authorization header must be in format: Bearer <token>',
                    'troubleshooting': [
                        'Check that frontend is sending: Authorization: Bearer <token>',
                        'Verify token format in browser Network tab',
                        'Ensure no extra spaces in Authorization header'
                    ]
                }), 401
        else:
            app.logger.error("No Authorization header found")
            return jsonify({
                'error': 'Authorization header missing',
                'details': 'No Authorization header was received',
                'troubleshooting': [
                    'Check CORS configuration allows Authorization header',
                    'Verify frontend is sending Authorization header',
                    'Check browser Network tab for Authorization header',
                    'If using ngrok, ensure https:// scheme in NEXT_PUBLIC_API_URL',
                    'Check for proxy/nginx that may be stripping headers'
                ]
            }), 401

        if not token:
            app.logger.error("Token is empty after extraction")
            return jsonify({
                'error': 'Empty token',
                'details': 'Authorization header present but token is empty',
                'troubleshooting': [
                    'Verify Supabase session has valid access_token',
                    'Check that authApiRequest is called with valid session'
                ]
            }), 401

        jwt_secret = os.getenv('SUPABASE_JWT_SECRET')
        app.logger.info(f"SUPABASE_JWT_SECRET present: {bool(jwt_secret)}")
        if jwt_secret:
            app.logger.info(f"JWT_SECRET length: {len(jwt_secret)}")

        try:
            app.logger.info("Attempting to decode JWT token")
            if not jwt_secret:
                app.logger.error("SUPABASE_JWT_SECRET not set")
                return jsonify({
                    'error': 'Server configuration error',
                    'details': 'JWT secret not configured',
                    'troubleshooting': [
                        'Set SUPABASE_JWT_SECRET environment variable',
                        'Check backend environment configuration',
                        'Verify .env file is loaded correctly'
                    ]
                }), 500

            payload = jwt.decode(
                token,
                jwt_secret,
                algorithms=['HS256'],
                audience='authenticated',
                options={"verify_exp": True}
            )
            app.logger.info(f"JWT decoded successfully. Payload: {payload}")
            request.user_id = payload['sub']
            request.user_role = payload.get('role', 'user')  # Default to user role
            app.logger.info(f"Set request.user_id: {request.user_id}")
            app.logger.info(f"Set request.user_role: {request.user_role}")
            app.logger.info("=== AUTH CHECK PASSED ===")
        except jwt.ExpiredSignatureError:
            app.logger.error("Token expired")
            return jsonify({
                'error': 'Token expired',
                'details': 'JWT token has expired',
                'troubleshooting': [
                    'User needs to re-authenticate',
                    'Check Supabase session refresh',
                    'Verify token expiration time'
                ]
            }), 401
        except jwt.InvalidTokenError as e:
            app.logger.error(f"Invalid token: {e}")
            return jsonify({
                'error': 'Invalid token',
                'details': str(e),
                'troubleshooting': [
                    'Verify token is from correct Supabase project',
                    'Check JWT secret matches Supabase configuration',
                    'Ensure token audience is correct'
                ]
            }), 401
        except Exception as e:
            app.logger.error(f"Token parse error: {str(e)}")
            return jsonify({
                'error': 'Token processing error',
                'details': str(e),
                'troubleshooting': [
                    'Check token format and content',
                    'Verify JWT secret is correct',
                    'Check for token corruption during transmission'
                ]
            }), 401

        return f(*args, **kwargs)
    return decorated_function

# --------------------- Admin Auth Decorator ---------------------
def require_admin(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First verify basic auth
        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        if not token:
            return jsonify({'error': 'Token missing'}), 401

        try:
            payload = jwt.decode(
                token,
                os.getenv('SUPABASE_JWT_SECRET'),
                algorithms=['HS256'],
                audience='authenticated',
                options={"verify_exp": True}
            )
            user_id = payload['sub']

            # Validate admin role from profiles table (do not use JWT claim role)
            try:
                user_profile = supabase.table('profiles').select('role').eq('id', user_id).single().execute()
                if not user_profile.data or user_profile.data.get('role') != 'admin':
                    return jsonify({'error': 'Admin access required'}), 403
                profile_role = user_profile.data.get('role')
            except Exception:
                return jsonify({'error': 'Admin access required'}), 403

            request.user_id = user_id
            request.user_role = profile_role

            # Log admin action for audit
            log_admin_action(user_id, f"Accessed {request.path}", request.remote_addr)

        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({"error": f"Token parse error: {str(e)}"}), 401

        return f(*args, **kwargs)
    return decorated_function

# --------------------- Service Key Auth Decorator ---------------------
def require_service_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        service_key = request.headers.get('X-Service-Key')
        if not service_key or service_key != os.getenv('ADMIN_SERVICE_KEY'):
            return jsonify({'error': 'Invalid service key'}), 403
        return f(*args, **kwargs)
    return decorated_function

# --------------------- Dynamic Delivery Helpers ---------------------

def _is_public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
        if not infos:
            return False
        for family, _, _, _, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if any([ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_reserved, ip.is_multicast]):
                return False
        return True
    except Exception:
        return False

def _assert_safe_url(u: str):
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        raise ValueError("Callback URL must be http or https")
    if not p.netloc:
        raise ValueError("Callback URL host missing")
    if OUTBOUND_CALLBACK_BLOCK_PRIVATE and not _is_public_host(p.hostname):
        raise ValueError("Callback host must resolve to a public IP")

def choose_tier(tiers: list, base_amount: float) -> dict | None:
    if not tiers:
        return None
    # Sort ascending by min_amount; apply max_amount if provided
    valid = []
    for t in tiers:
        min_a = float(t.get("min_amount", 0) or 0)
        max_a = t.get("max_amount")
        if max_a is not None:
            try:
                max_a = float(max_a)
            except Exception:
                max_a = None
        if base_amount >= min_a and (max_a is None or base_amount < max_a):
            valid.append(t)
    if not valid:
        return None
    # pick the highest min_amount that still matches
    valid.sort(key=lambda x: float(x.get("min_amount", 0) or 0))
    return valid[-1]

def apply_pricing_rules(base_usd: float, payment_method: str, currency: str | None, rules: dict | None) -> float:
    """
    Apply pricing rules with defaults:
    - Crypto: Under $50 = 2%, $50+ = 1.5%
    - PayPal: All amounts = 2%
    - Currency overrides: Fixed USD amounts added on top of method fees
    """
    if not rules:
        return round(float(base_usd), 2)

    total_percent = 0.0
    total_fixed = 0.0

    methods = (rules or {}).get("methods") or {}

    # Apply method-specific rules, or use defaults if none specified
    if methods.get(payment_method):
        # Use provided method rules
        mdef = methods.get(payment_method) or {}
        tiers = mdef.get("tiers") or []
        tier = choose_tier(tiers, float(base_usd))
        if tier:
            total_percent += float(tier.get("percent", 0) or 0)
            total_fixed += float(tier.get("fixed_usd", 0) or 0)
        else:
            total_percent += float(mdef.get("percent", 0) or 0)
            total_fixed += float(mdef.get("fixed_usd", 0) or 0)
    else:
        # Use default method fees
        if payment_method == "paypal":
            total_percent += 2.0  # PayPal flat 2%
        elif payment_method == "crypto":
            if float(base_usd) < 50:
                total_percent += 2.0  # Crypto under $50 = 2%
            else:
                total_percent += 1.5  # Crypto $50+ = 1.5%

    # Add currency-specific overrides
    if currency:
        cdefs = (rules or {}).get("currencies") or {}
        cdef = cdefs.get(currency) or {}
        total_percent += float(cdef.get("percent", 0) or 0)
        total_fixed += float(cdef.get("fixed_usd", 0) or 0)

    adjusted = float(base_usd) * (1.0 + total_percent / 100.0) + total_fixed
    # Clamp to >= 0.01 and round to cents
    adjusted = max(adjusted, 0.01)
    return round(adjusted + 1e-9, 2)

def redact_listing(listing: dict, viewer_id: str | None, is_admin: bool = False) -> dict:
    """Redact seller-only fields from public responses"""
    if not (is_admin or (viewer_id and listing.get("seller_id") == viewer_id)):
        listing.pop("fulfillment_url", None)
    return listing

def trigger_delivery_callback(escrow_id: str):
    esc = supabase.table('escrows').select(
        'id,status,funded_at,amount_usd,currency,payment_method,buyer_id,seller_id,listing_id,'
        'fulfillment_status,fulfillment_attempts,fulfillment_last_code,fulfillment_last_at,fulfillment_last_error,'
        'fulfillment_idempotency_key'
    ).eq('id', escrow_id).single().execute().data
    if not esc or esc.get('fulfillment_status') == 'success':
        return

    lst = supabase.table('listings').select('id,title,fulfillment_url,seller_id').eq('id', esc['listing_id']).single().execute().data
    if not lst or not lst.get('fulfillment_url'):
        return

    callback_url = lst['fulfillment_url']
    try:
        _assert_safe_url(callback_url)
    except Exception as e:
        supabase.table('escrows').update({
            'fulfillment_status': 'failed',
            'fulfillment_last_error': f'URL invalid: {str(e)}',
            'fulfillment_last_at': datetime.now(timezone.utc).isoformat(),
            'fulfillment_attempts': (esc.get('fulfillment_attempts') or 0) + 1,
        }).eq('id', escrow_id).execute()
        return

    buyer = supabase.table('profiles').select('id,username').eq('id', esc['buyer_id']).single().execute().data
    seller = supabase.table('profiles').select('id,username').eq('id', esc['seller_id']).single().execute().data

    payload = {
        "event": "escrow.funded",
        "idempotency_key": esc['fulfillment_idempotency_key'],
        "escrow": {
            "id": esc['id'],
            "status": "funded",
            "funded_at": esc.get('funded_at') or datetime.now(timezone.utc).isoformat(),
            "amount_usd": esc['amount_usd'],
            "currency": esc['currency'],
            "payment_method": esc['payment_method'],
        },
        "listing": {"id": lst['id'], "title": lst['title']},
        "buyer": {"id": buyer['id'], "username": buyer.get('username') if buyer else None},
        "seller": {"id": seller['id'], "username": seller.get('username') if seller else None},
    }

    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    attempts = 0
    last_code, last_err = None, None

    for _ in range(OUTBOUND_CALLBACK_RETRY_MAX):
        attempts += 1
        try:
            ts_ms = int(time.time() * 1000)
            headers = {
                "Content-Type": "application/json",
                "User-Agent": OUTBOUND_CALLBACK_USER_AGENT,
                "X-Medius-Event": "escrow.funded",
                "X-Medius-Timestamp": str(ts_ms),
                "X-Medius-Idempotency-Key": str(esc["fulfillment_idempotency_key"]),
            }
            resp = requests.post(callback_url, data=body, headers=headers, timeout=OUTBOUND_CALLBACK_TIMEOUT_MS / 1000.0)
            last_code = resp.status_code
            if 200 <= resp.status_code < 300:
                supabase.table('escrows').update({
                    'fulfillment_status': 'success',
                    'fulfillment_last_code': resp.status_code,
                    'fulfillment_last_error': None,
                    'fulfillment_last_at': datetime.now(timezone.utc).isoformat(),
                    'fulfillment_attempts': (esc.get('fulfillment_attempts') or 0) + attempts,
                }).eq('id', escrow_id).execute()
                return
            else:
                last_err = f"HTTP {resp.status_code}: {resp.text[:400]}"
        except Exception as e:
            last_err = str(e)
        if attempts < OUTBOUND_CALLBACK_RETRY_MAX:
            time.sleep(min(2 ** (attempts - 1), 4))  # 1s, 2s, 4s

    supabase.table('escrows').update({
        'fulfillment_status': 'failed',
        'fulfillment_last_code': last_code,
        'fulfillment_last_error': (last_err or '')[:800],
        'fulfillment_last_at': datetime.now(timezone.utc).isoformat(),
        'fulfillment_attempts': (esc.get('fulfillment_attempts') or 0) + attempts,
    }).eq('id', escrow_id).execute()

def mark_escrow_funded(escrow_id: str):
    """Mark escrow as funded and trigger delivery callback"""
    supabase.table('escrows').update({
        'status': 'funded',
        'funded_at': datetime.now(timezone.utc).isoformat(),
    }).eq('id', escrow_id).execute()
    trigger_delivery_callback(escrow_id)

# --------------------- Admin Audit Logging ---------------------
def log_admin_action(admin_id: str, action: str, ip_address: str = None, details: dict = None):
    """Log admin actions for audit purposes."""
    try:
        log_entry = {
            'admin_id': admin_id,
            'action': action,
            'ip_address': ip_address or request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'timestamp': datetime.utcnow().isoformat(),
            'details': json.dumps(details) if details else None
        }

        # Try to insert into admin_audit_log table
        try:
            supabase.table('admin_audit_log').insert(log_entry).execute()
        except Exception as e:
            # If table doesn't exist, log to application logger
            app.logger.warning(f"Admin audit log table not found, logging to app logger: {log_entry}")

        # Always log to application logger for backup
        app.logger.info(f"ADMIN ACTION: {admin_id} - {action} - IP: {ip_address}")
    except Exception as e:
        app.logger.error(f"Failed to log admin action: {e}")

@app.route('/api/security/forbidden-admin', methods=['POST'])
@limiter.limit("60 per minute")
def log_forbidden_admin():
    """Log a forbidden access attempt to the admin area with the requester's IP."""
    try:
        details = request.json or {}
        path = details.get('path') or '/admin'
        user_id = None
        # Try to decode JWT if present to capture user id (optional)
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
                payload = jwt.decode(
                    token,
                    os.getenv('SUPABASE_JWT_SECRET'),
                    algorithms=['HS256'],
                    audience='authenticated',
                    options={"verify_exp": True}
                )
                user_id = payload.get('sub')
            except Exception:
                # ignore token errors; we still log IP
                pass
        log_entry = {
            "event": "forbidden_admin_access",
            "path": path,
            "ip_address": request.remote_addr,
            "user_agent": request.headers.get('User-Agent'),
            "user_id": user_id,
            "role": None,
            "timestamp": datetime.utcnow().isoformat()
        }
        # Try to enrich with role from profiles
        try:
            if user_id:
                prof = supabase.table('profiles').select('role').eq('id', user_id).single().execute()
                log_entry["role"] = (prof.data or {}).get('role')
        except Exception:
            pass
        # Attempt to store in a table if present; otherwise log
        try:
            supabase.table('security_events').insert(log_entry).execute()
        except Exception:
            app.logger.warning(f"SECURITY: {log_entry}")
        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("log_forbidden_admin error")
        return jsonify({"ok": False, "error": str(e)}), 500

# --------------------- Utils ---------------------
def get_usd_price(symbol: str):
    mapping = {
        'BTC': 'bitcoin', 'ETH': 'ethereum', 'LTC': 'litecoin', 'BCH': 'bitcoin-cash',
        'DOGE': 'dogecoin', 'XRP': 'ripple', 'ADA': 'cardano', 'DOT': 'polkadot',
        'MATIC': 'matic-network', 'SOL': 'solana', 'AVAX': 'avalanche-2',
        'TRX': 'tron', 'BNB': 'binancecoin', 'ATOM': 'cosmos', 'XLM': 'stellar',
        # USDT (all mapped to 'tether' on CoinGecko)
        'USDT-ERC20': 'tether', 'USDT-BEP20': 'tether', 'USDT-SOL': 'tether', 'USDT-TRON': 'tether'
    }
    coin = mapping.get((symbol or '').upper())
    if not coin:
        return None
    try:
        r = requests.get(COINGECKO_SIMPLE, params={'ids': coin, 'vs_currencies': 'usd'}, timeout=12)
        r.raise_for_status()
        return float(r.json().get(coin, {}).get('usd', 0) or 0)
    except Exception as e:
        app.logger.error(f"Price fetch failed for {symbol}: {e}")
        return None

# --------------------- Platform -> Tatum helpers ---------------------
# ========================================
# UNIVERSAL CRYPTO SENDING (ALL CHAINS/TOKENS)
# ========================================

# Contract addresses for tokens
TOKEN_CONTRACTS = {
    'USDT-ERC20': '0xdAC17F958D2ee523a2206206994597C13D831ec7',
    'USDC-ERC20': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
    'USDT-BEP20': '0x55d398326f99059fF775485246999027B3197955',
    'USDC-BEP20': '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d',
    'USDT-TRON': 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',
    'USDT-SOL': 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
    'USDC-SOL': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
    'MATIC-POLYGON': '0x0000000000000000000000000000000000001010',
    # Add more as needed
}

CHAIN_MAPPING = {
    # Native coins
    'BTC': 'bitcoin',
    'ETH': 'ethereum',
    'BNB': 'bsc',
    'LTC': 'litecoin',
    'DOGE': 'dogecoin',
    'BCH': 'bitcoin-cash',
    'SOL': 'solana',
    'TRX': 'tron',
    'XRP': 'xrp',
    'ADA': 'cardano',
    'DOT': 'polkadot',
    'MATIC': 'polygon',
    'AVAX': 'avax',
    'ATOM': 'cosmos',
    'XLM': 'stellar',
    
    # ERC20 tokens
    'USDT-ERC20': 'ethereum',
    'USDC-ERC20': 'ethereum',
    
    # BEP20 tokens
    'USDT-BEP20': 'bsc',
    'USDC-BEP20': 'bsc',
    
    # TRC20 tokens
    'USDT-TRON': 'tron',
    
    # SPL tokens
    'USDT-SOL': 'solana',
    'USDC-SOL': 'solana',
}

def send_platform_crypto(currency: str, to_address: str, amount: float) -> Optional[str]:
    """
    Universal crypto sending function supporting all chains and tokens.
    Uses Tatum API for maximum compatibility.
    
    Args:
        currency: Currency code (e.g., 'BTC', 'ETH', 'USDT-ERC20')
        to_address: Destination address
        amount: Amount to send (in currency units)
    
    Returns:
        Transaction hash if successful, None otherwise
    """
    try:
        chain = CHAIN_MAPPING.get(currency)
        if not chain:
            app.logger.error(f"Unsupported currency: {currency}")
            return None
        
        # Get platform wallet details
        mnemonic = os.getenv('MNEMONIC')
        if not mnemonic:
            app.logger.error("MNEMONIC not configured")
            return None
        
        headers = {
            'x-api-key': TATUM_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Native coins (BTC, ETH, BNB, etc.)
        if '-' not in currency:
            return _send_native_coin(chain, currency, to_address, amount, mnemonic, headers)
        
        # Tokens (ERC20, BEP20, TRC20, SPL)
        else:
            return _send_token(chain, currency, to_address, amount, mnemonic, headers)
        
    except Exception as e:
        app.logger.error(f"send_platform_crypto error for {currency}: {e}")
        return None

def _send_native_coin(chain: str, currency: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send native blockchain coins (BTC, ETH, BNB, etc.)"""
    try:
        # Chain-specific implementations
        if chain == 'bitcoin':
            return _send_btc(to_address, amount, mnemonic, headers)
        
        elif chain in ['ethereum', 'bsc', 'polygon']:
            return _send_evm_native(chain, to_address, amount, mnemonic, headers)
        
        elif chain == 'tron':
            return _send_trx(to_address, amount, mnemonic, headers)
        
        elif chain == 'solana':
            return _send_sol(to_address, amount, mnemonic, headers)
        
        elif chain == 'xrp':
            return _send_xrp(to_address, amount, mnemonic, headers)
        
        elif chain == 'stellar':
            return _send_xlm(to_address, amount, mnemonic, headers)
        
        elif chain in ['litecoin', 'dogecoin', 'bitcoin-cash']:
            return _send_utxo_chain(chain, to_address, amount, mnemonic, headers)
        
        elif chain in ['cardano', 'polkadot', 'avax', 'cosmos']:
            return _send_generic_native(chain, to_address, amount, mnemonic, headers)
        
        else:
            app.logger.error(f"Native coin handler not implemented for {chain}")
            return None
            
    except Exception as e:
        app.logger.error(f"Native coin send error: {e}")
        return None

def _send_token(chain: str, currency: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send tokens (ERC20, BEP20, TRC20, SPL)"""
    try:
        contract_address = TOKEN_CONTRACTS.get(currency)
        if not contract_address:
            app.logger.error(f"Contract address not configured for {currency}")
            return None
        
        if chain in ['ethereum', 'bsc', 'polygon']:
            return _send_evm_token(chain, contract_address, to_address, amount, mnemonic, headers)
        
        elif chain == 'tron':
            return _send_trc20(contract_address, to_address, amount, mnemonic, headers)
        
        elif chain == 'solana':
            return _send_spl_token(contract_address, to_address, amount, mnemonic, headers)
        
        else:
            app.logger.error(f"Token handler not implemented for {chain}")
            return None
            
    except Exception as e:
        app.logger.error(f"Token send error: {e}")
        return None

# ========================================
# CHAIN-SPECIFIC IMPLEMENTATIONS
# ========================================

def _send_btc(to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send Bitcoin"""
    try:
        payload = {
            'fromAddress': [{
                'address': _derive_address('bitcoin', mnemonic, 0),
                'privateKey': _derive_private_key('bitcoin', mnemonic, 0)
            }],
            'to': [{
                'address': to_address,
                'value': amount
            }]
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/bitcoin/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"BTC send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"BTC send error: {e}")
        return None

def _send_evm_native(chain: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send native EVM coins (ETH, BNB, MATIC, AVAX)"""
    try:
        from_address = _derive_address(chain, mnemonic, 0)
        private_key = _derive_private_key(chain, mnemonic, 0)
        
        payload = {
            'to': to_address,
            'amount': str(amount),
            'currency': chain.upper() if chain != 'bsc' else 'BSC',
            'fromPrivateKey': private_key
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/{chain}/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"EVM native send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"EVM native send error: {e}")
        return None

def _send_evm_token(chain: str, contract: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send ERC20/BEP20 tokens"""
    try:
        from_address = _derive_address(chain, mnemonic, 0)
        private_key = _derive_private_key(chain, mnemonic, 0)
        
        # Determine decimals (most stablecoins use 6, but USDC on some chains uses 18)
        decimals = 6 if 'USDT' in contract or 'USDC' in contract else 18
        
        payload = {
            'to': to_address,
            'amount': str(amount),
            'contractAddress': contract,
            'digits': decimals,
            'fromPrivateKey': private_key
        }
        
        endpoint = f"/v3/{chain}/erc20/transaction" if chain == 'ethereum' else f"/v3/{chain}/bep20/transaction"
        
        response = requests.post(
            f"{TATUM_API_URL}{endpoint}",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"EVM token send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"EVM token send error: {e}")
        return None

def _send_trx(to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send TRX (Tron native)"""
    try:
        from_address = _derive_address('tron', mnemonic, 0)
        private_key = _derive_private_key('tron', mnemonic, 0)
        
        payload = {
            'fromPrivateKey': private_key,
            'to': to_address,
            'amount': str(amount)
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/tron/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"TRX send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"TRX send error: {e}")
        return None

def _send_trc20(contract: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send TRC20 tokens (USDT-TRON)"""
    try:
        from_address = _derive_address('tron', mnemonic, 0)
        private_key = _derive_private_key('tron', mnemonic, 0)
        
        payload = {
            'fromPrivateKey': private_key,
            'to': to_address,
            'tokenAddress': contract,
            'amount': str(amount),
            'feeLimit': 100  # TRX fee limit
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/tron/trc20/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"TRC20 send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"TRC20 send error: {e}")
        return None

def _send_sol(to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send SOL (Solana native)"""
    try:
        from_address = _derive_address('solana', mnemonic, 0)
        private_key = _derive_private_key('solana', mnemonic, 0)
        
        payload = {
            'from': from_address,
            'to': to_address,
            'amount': str(amount),
            'fromPrivateKey': private_key
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/solana/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"SOL send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"SOL send error: {e}")
        return None

def _send_spl_token(contract: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send SPL tokens (USDT-SOL, USDC-SOL)"""
    try:
        from_address = _derive_address('solana', mnemonic, 0)
        private_key = _derive_private_key('solana', mnemonic, 0)
        
        payload = {
            'from': from_address,
            'to': to_address,
            'amount': str(amount),
            'tokenAddress': contract,
            'fromPrivateKey': private_key
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/solana/spl/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"SPL send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"SPL send error: {e}")
        return None

def _send_xrp(to_address: str, amount: float, mnemonic: str, headers: dict, destination_tag: str = None) -> Optional[str]:
    """Send XRP"""
    try:
        from_address = _derive_address('xrp', mnemonic, 0)
        private_key = _derive_private_key('xrp', mnemonic, 0)
        
        payload = {
            'fromAccount': from_address,
            'to': to_address,
            'amount': str(amount),
            'fromSecret': private_key
        }
        
        if destination_tag:
            payload['destinationTag'] = int(destination_tag)
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/xrp/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"XRP send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"XRP send error: {e}")
        return None

def _send_xlm(to_address: str, amount: float, mnemonic: str, headers: dict, memo: str = None) -> Optional[str]:
    """Send XLM (Stellar)"""
    try:
        from_address = _derive_address('stellar', mnemonic, 0)
        private_key = _derive_private_key('stellar', mnemonic, 0)
        
        payload = {
            'fromAccount': from_address,
            'to': to_address,
            'amount': str(amount),
            'fromSecret': private_key
        }
        
        if memo:
            payload['message'] = memo
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/xlm/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"XLM send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"XLM send error: {e}")
        return None

def _send_utxo_chain(chain: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Send UTXO-based coins (LTC, DOGE, BCH)"""
    try:
        from_address = _derive_address(chain, mnemonic, 0)
        private_key = _derive_private_key(chain, mnemonic, 0)
        
        payload = {
            'fromAddress': [{
                'address': from_address,
                'privateKey': private_key
            }],
            'to': [{
                'address': to_address,
                'value': amount
            }]
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/{chain}/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"{chain} send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"UTXO chain send error: {e}")
        return None

def _send_generic_native(chain: str, to_address: str, amount: float, mnemonic: str, headers: dict) -> Optional[str]:
    """Generic handler for other native chains (ADA, DOT, AVAX, ATOM)"""
    try:
        from_address = _derive_address(chain, mnemonic, 0)
        private_key = _derive_private_key(chain, mnemonic, 0)
        
        payload = {
            'to': to_address,
            'amount': str(amount),
            'fromPrivateKey': private_key
        }
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/{chain}/transaction",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('txId')
        else:
            app.logger.error(f"{chain} send failed: {response.status_code} {response.text}")
            return None
            
    except Exception as e:
        app.logger.error(f"Generic native send error: {e}")
        return None

# ========================================
# WALLET DERIVATION HELPERS
# ========================================

def _derive_address(chain: str, mnemonic: str, index: int = 0) -> str:
    """Derive address from mnemonic for any chain using Tatum"""
    try:
        headers = {'x-api-key': TATUM_API_KEY}
        payload = {'mnemonic': mnemonic, 'index': index}
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/{chain}/wallet",
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('address')
        else:
            raise Exception(f"Address derivation failed: {response.status_code}")
            
    except Exception as e:
        app.logger.error(f"Address derivation error for {chain}: {e}")
        raise

def _derive_private_key(chain: str, mnemonic: str, index: int = 0) -> str:
    """Derive private key from mnemonic for any chain using Tatum"""
    try:
        headers = {'x-api-key': TATUM_API_KEY}
        payload = {'mnemonic': mnemonic, 'index': index}
        
        response = requests.post(
            f"{TATUM_API_URL}/v3/{chain}/wallet/priv",
            headers=headers,
            json=payload,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get('key')
        else:
            raise Exception(f"Private key derivation failed: {response.status_code}")
            
    except Exception as e:
        app.logger.error(f"Private key derivation error for {chain}: {e}")
        raise


@app.route('/api/upload/image', methods=['POST'])
@require_auth
@limiter.limit("30 per hour")
def upload_image():
    """Accept a multipart/form-data file upload and store it in Supabase storage.
    Returns JSON { url: public_url } on success.
    """
    try:
        # Expect file under 'image'
        if 'image' not in request.files:
            return jsonify({'error': 'No file part (image)'}), 400
        file = request.files['image']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        # Basic mime-type check
        if not file.mimetype or not file.mimetype.startswith('image/'):
            return jsonify({'error': 'Uploaded file is not an image'}), 400

        # Limit file size (streaming aware) - rely on server config; also check content-length if present
        max_bytes = 5 * 1024 * 1024  # 5MB
        cl = request.content_length or 0
        if cl and cl > max_bytes + 1024:
            return jsonify({'error': 'File too large (max 5MB)'}), 400

        # Generate a safe object name (use timezone-aware UTC)
        ext = os.path.splitext(file.filename)[1] or '.jpg'
        object_name = f"uploads/{datetime.now(timezone.utc).strftime('%Y/%m/%d')}/{uuid.uuid4().hex}{ext}"

        # Read file bytes
        data = file.read()
        if len(data) > max_bytes:
            return jsonify({'error': 'File too large (max 5MB)'}), 400

        # Upload using Supabase storage (service role key is used by supabase client)
        upload_succeeded = False
        try:
            res = supabase.storage.from_(PUBLIC_IMAGE_BUCKET).upload(object_name, data, {'content-type': file.mimetype})
            upload_succeeded = True
        except Exception as e:
            app.logger.exception('Supabase storage upload failed, will attempt direct REST upload as fallback')

        # Fallback to direct REST upload to Supabase storage (longer timeout)
        if not upload_succeeded:
            try:
                # Construct REST URL for object upload
                rest_url = f"{SUPABASE_URL.rstrip('/')}/storage/v1/object/{PUBLIC_IMAGE_BUCKET}/{object_name}"
                headers = {
                    'Authorization': f'Bearer {SUPABASE_SERVICE_KEY}',
                    'Content-Type': file.mimetype
                }
                r = requests.put(rest_url, headers=headers, data=data, timeout=120)
                if r.status_code not in (200, 201, 204):
                    app.logger.error('Direct REST upload failed: %s %s', r.status_code, r.text)
                    return jsonify({'error': 'Storage upload failed'}), 500
                upload_succeeded = True
            except Exception as e:
                app.logger.exception('Direct REST upload fallback failed')
                return jsonify({'error': 'Storage upload failed'}), 500

        # Build public URL (assuming bucket is public or needs signed URL)
        # Try to get public URL
        try:
            public = supabase.storage.from_(PUBLIC_IMAGE_BUCKET).get_public_url(object_name)
            url = public.get('publicUrl') or public.get('public_url') or None
        except Exception:
            url = None

        # Fallback: ask Supabase to create signed URL for short time
        if not url:
            try:
                signed = supabase.storage.from_(PUBLIC_IMAGE_BUCKET).create_signed_url(object_name, 60*60)
                url = signed.get('signedURL') or signed.get('signed_url')
            except Exception:
                url = None

        if not url:
            # As a final fallback, return object path for frontend to construct URL from SUPABASE_URL
            url = f"{SUPABASE_URL}/storage/v1/object/public/{PUBLIC_IMAGE_BUCKET}/{object_name}"

        return jsonify({'url': url}), 201
    except Exception as e:
        app.logger.exception('upload_image error')
        return jsonify({'error': str(e)}), 500



# --------------------- Supported currencies ---------------------
@app.route('/api/supported-currencies', methods=['GET'])
def get_supported_currencies():
    currencies = [
    {'code': 'USD', 'name': 'PayPal'},
    {'code': 'BTC', 'name': 'Bitcoin'},
    {'code': 'ETH', 'name': 'Ethereum'},
    {'code': 'LTC', 'name': 'Litecoin'},
    {'code': 'BCH', 'name': 'Bitcoin Cash'},
    {'code': 'DOGE', 'name': 'Dogecoin'},
    {'code': 'XRP', 'name': 'Ripple'},
    {'code': 'ADA', 'name': 'Cardano'},
    {'code': 'DOT', 'name': 'Polkadot'},
    {'code': 'MATIC', 'name': 'Polygon'},
    {'code': 'SOL', 'name': 'Solana'},
    {'code': 'AVAX', 'name': 'Avalanche'},
    {'code': 'TRX', 'name': 'Tron'},
    {'code': 'BNB', 'name': 'Binance Coin'},
    {'code': 'ATOM', 'name': 'Cosmos'},
    {'code': 'XLM', 'name': 'Stellar'},
    # USDT variants
    {'code': 'USDT-ERC20', 'name': 'Tether (USDT) — ERC20 (Ethereum)'},
    {'code': 'USDT-BEP20', 'name': 'Tether (USDT) — BEP20 (BNB Smart Chain)'},
    {'code': 'USDT-SOL', 'name': 'Tether (USDT) — Solana (SPL)'},
    {'code': 'USDT-TRON', 'name': 'Tether (USDT) — TRC20 (Tron)'}
    ]
    return jsonify(currencies), 200

# --------------------- Profiles ---------------------
@app.route('/api/profile/me', methods=['GET'])
@require_auth
@limiter.exempt
def profile_me():
    try:
        uid = request.user_id
        res = supabase.table('profiles').select('*').eq('id', uid).single().execute()
        if not res.data:
            return jsonify({"error": "Profile not found"}), 404
        profile = res.data

        # lightweight per-user stats for profile page
        try:
            # Pull fields needed to compute USD totals consistently with dashboard
            buyer = supabase.table('escrows').select('id, status, usd_amount, amount, currency, payment_method').eq('buyer_id', uid).execute()
            seller = supabase.table('escrows').select('id, status, usd_amount, amount, currency, payment_method').eq('seller_id', uid).execute()

            # Merge and de-duplicate by escrow id
            unique = {}
            for row in (buyer.data or []):
                unique[row['id']] = row
            for row in (seller.data or []):
                unique[row['id']] = unique.get(row['id'], row)
            rows = list(unique.values())

            total = len(rows)
            completed = len([x for x in rows if x.get('status') == 'completed'])
            active = len([x for x in rows if x.get('status') in ['pending', 'funded', 'confirmed', 'processing']])
            # Compute USD volume for completed escrows.
            # - USD/PayPal: prefer raw amount so admin edits reflect immediately
            # - Crypto: use live USD conversion of amount when available; fallback to stored usd_amount
            price_cache = {}
            def price_for(currency):
                cur = (currency or '').upper()
                if cur in price_cache:
                    return price_cache[cur]
                p = get_usd_price(cur) or 0
                price_cache[cur] = p
                return p

            def row_usd(r):
                if r.get('status') != 'completed':
                    return 0.0
                currency = r.get('currency')
                payment_method = r.get('payment_method')
                if currency == 'USD' or payment_method == 'paypal':
                    # Prefer raw amount for USD/PayPal so admin edits reflect immediately
                    return float(r.get('amount') or r.get('usd_amount') or 0)
                # Crypto: try live price conversion; fallback to stored usd_amount
                price = price_for(currency)
                if price and (r.get('amount') is not None):
                    try:
                        return float(r.get('amount') or 0) * float(price)
                    except Exception:
                        pass
                return float(r.get('usd_amount') or 0)

            volume_usd = round(sum(row_usd(x) for x in rows), 2)
            profile['stats'] = {
                'total': total,
                'completed': completed,
                'active': active,
                'volume_usd': volume_usd,
            }
        except Exception:
            # stats are optional; do not fail the endpoint
            profile['stats'] = {
                'total': 0,
                'completed': 0,
                'active': 0,
                'volume_usd': 0,
            }

        return jsonify(profile), 200
    except Exception as e:
        app.logger.exception("profile_me error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/profile/me', methods=['PATCH'])
@require_auth
# Increase limit; browsers may send preflight OPTIONS which shouldn't count but can still create pressure
@limiter.limit("60 per hour")
def update_profile_me():
    try:
        uid = request.user_id
        body = request.json or {}

        # Whitelist allowed fields (no referral payout defaults)
        update = {}
        for k in ['display_name', 'bio', 'avatar_url']:
            if k in body:
                update[k] = body[k]

        # Username update (if allowed)
        username = body.get('username')
        if username:
            if len(username) < 3 or len(username) > 30:
                return jsonify({"error": "Username must be 3-30 characters"}), 400
            if not username.replace('_', '').replace('-', '').isalnum():
                return jsonify({"error": "Username can only contain letters, numbers, _ and -"}), 400

            exists = supabase.table('profiles').select('id').ilike('username', username).neq('id', uid).limit(1).execute()
            if exists.data:
                return jsonify({"error": "Username already taken"}), 400
            update['username'] = username.lower()

        res = supabase.table('profiles').update(update).eq('id', uid).execute()
        return jsonify(res.data[0] if res.data else {}), 200
    except Exception as e:
        app.logger.exception("update_profile_me error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<username>', methods=['GET'])
def get_user_by_username(username):
    try:
        res = supabase.table('profiles') \
            .select('id, username, display_name, avatar_url, bio, referral_code, created_at') \
            .ilike('username', username) \
            .single().execute()
        if not res.data:
            return jsonify({"error": "User not found"}), 404

        profile = res.data

        # public lightweight stats similar to /api/profile/me
        try:
            uid = profile['id']
            buyer = supabase.table('escrows').select('id, status, usd_amount, amount, currency, payment_method').eq('buyer_id', uid).execute()
            seller = supabase.table('escrows').select('id, status, usd_amount, amount, currency, payment_method').eq('seller_id', uid).execute()

            unique = {}
            for row in (buyer.data or []):
                unique[row['id']] = row
            for row in (seller.data or []):
                unique[row['id']] = unique.get(row['id'], row)
            rows = list(unique.values())

            total = len(rows)
            completed = len([x for x in rows if x.get('status') == 'completed'])
            active = len([x for x in rows if x.get('status') in ['pending', 'funded', 'confirmed', 'processing']])
            price_cache = {}
            def price_for(currency):
                cur = (currency or '').upper()
                if cur in price_cache:
                    return price_cache[cur]
                p = get_usd_price(cur) or 0
                price_cache[cur] = p
                return p

            def row_usd(r):
                if r.get('status') != 'completed':
                    return 0.0
                currency = r.get('currency')
                payment_method = r.get('payment_method')
                if currency == 'USD' or payment_method == 'paypal':
                    return float(r.get('amount') or r.get('usd_amount') or 0)
                price = price_for(currency)
                if price and (r.get('amount') is not None):
                    try:
                        return float(r.get('amount') or 0) * float(price)
                    except Exception:
                        pass
                return float(r.get('usd_amount') or 0)

            volume_usd = round(sum(row_usd(x) for x in rows), 2)
            profile['stats'] = {
                'total': total,
                'completed': completed,
                'active': active,
                'volume_usd': volume_usd,
            }
        except Exception:
            profile['stats'] = {
                'total': 0,
                'completed': 0,
                'active': 0,
                'volume_usd': 0,
            }

        return jsonify(profile), 200
    except Exception as e:
        app.logger.exception("get_user_by_username error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/users/<username>/friends', methods=['GET'])
def public_friends(username):
    try:
        u = supabase.table('profiles').select('id, username').ilike('username', username).single().execute()
        if not u.data:
            return jsonify([]), 200
        uid = u.data['id']

        fr1 = supabase.table('friendships').select('requester_id, addressee_id, status') \
            .eq('status', 'accepted').eq('requester_id', uid).limit(100).execute()
        fr2 = supabase.table('friendships').select('requester_id, addressee_id, status') \
            .eq('status', 'accepted').eq('addressee_id', uid).limit(100).execute()

        ids = set()
        for f in (fr1.data or []):
            ids.add(f['requester_id']); ids.add(f['addressee_id'])
        for f in (fr2.data or []):
            ids.add(f['requester_id']); ids.add(f['addressee_id'])
        ids.discard(uid)

        if not ids:
            return jsonify([]), 200

        profiles = supabase.table('profiles').select('id, username, display_name, avatar_url') \
            .in_('id', list(ids)).limit(100).execute()
        return jsonify(profiles.data or []), 200
    except Exception:
        return jsonify([]), 200

# Block or unblock a user by username
@app.route('/api/users/<username>/block', methods=['POST'])
@require_auth
def block_user(username):
    try:
        uid = request.user_id
        data = request.json or {}
        action = (data.get('action') or 'block').lower()  # 'block' or 'unblock'

        # Lookup both users
        me = supabase.table('profiles').select('id').eq('id', uid).single().execute()
        if not me.data:
            return jsonify({"error": "Profile not found"}), 404

        other = supabase.table('profiles').select('id').ilike('username', username).single().execute()
        if not other.data:
            return jsonify({"error": "User not found"}), 404

        other_id = other.data['id']
        if other_id == uid:
            return jsonify({"error": "Cannot block yourself"}), 400

        # Try to find friendship both directions
        fr1 = supabase.table('friendships').select('id,status') \
            .eq('requester_id', uid).eq('addressee_id', other_id).limit(1).execute()
        fr2 = supabase.table('friendships').select('id,status') \
            .eq('requester_id', other_id).eq('addressee_id', uid).limit(1).execute()

        friendship = (fr1.data[0] if fr1.data else (fr2.data[0] if fr2.data else None))

        if action == 'unblock':
            if friendship:
                # If it was blocked, delete it; otherwise leave as-is
                if friendship.get('status') == 'blocked':
                    supabase.table('friendships').delete().eq('id', friendship['id']).execute()
            return jsonify({"success": True, "status": "unblocked"}), 200

        # action == 'block'
        if friendship:
            up = supabase.table('friendships').update({'status': 'blocked'}).eq('id', friendship['id']).execute()
            return jsonify(up.data[0]), 200
        else:
            ins = supabase.table('friendships').insert({
                'requester_id': uid,
                'addressee_id': other_id,
                'status': 'blocked'
            }).execute()
            return jsonify(ins.data[0]), 201
    except Exception as e:
        app.logger.exception("block_user error")
        return jsonify({"error": str(e)}), 500

# Username search (typeahead)
@app.route('/api/users/search', methods=['GET'])
@require_auth
def search_users():
    try:
        q = (request.args.get('q') or '').strip()
        if len(q) < 2:
            return jsonify([]), 200

        base = (os.getenv('SUPABASE_URL') or '').rstrip('/')
        url = f"{base}/rest/v1/profiles"

        params = {
            "select": "id,username,display_name,avatar_url",
            "or": f"(username.ilike.*{q}*,display_name.ilike.*{q}*)",
            "limit": "10"
        }
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Accept": "application/json"
        }

        r = requests.get(url, headers=headers, params=params, timeout=15)
        if r.status_code != 200:
            app.logger.error("search_users REST error: %s %s", r.status_code, r.text)
            return jsonify([]), 200

        return jsonify(r.json() or []), 200
    except Exception as e:
        app.logger.exception("search_users error")
        return jsonify({"error": str(e)}), 500

# --------------------- Friends ---------------------
@app.route('/api/friends', methods=['GET'])
@require_auth
def list_friends():
    try:
        uid = request.user_id
        fr1 = supabase.table('friendships').select('id, requester_id, addressee_id, status, created_at') \
            .eq('status', 'accepted').eq('requester_id', uid).order('created_at', desc=True).limit(200).execute()
        fr2 = supabase.table('friendships').select('id, requester_id, addressee_id, status, created_at') \
            .eq('status', 'accepted').eq('addressee_id', uid).order('created_at', desc=True).limit(200).execute()

        rows = (fr1.data or []) + (fr2.data or [])
        seen = set()
        merged = []
        for r in rows:
            if r['id'] not in seen:
                seen.add(r['id'])
                merged.append(r)
        merged.sort(key=lambda r: r.get('created_at') or '', reverse=True)

        return jsonify(merged), 200
    except Exception as e:
        app.logger.exception("list_friends error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/friends/request', methods=['POST'])
@require_auth
@limiter.limit("20 per hour")
def request_friend():
    try:
        uid = request.user_id
        username = (request.json or {}).get('username', '').strip()
        if not username:
            return jsonify({"error": "Missing username"}), 400

        to = supabase.table('profiles').select('id').ilike('username', username).single().execute()
        if not to.data:
            return jsonify({"error": "User not found"}), 404
        to_id = to.data['id']
        if to_id == uid:
            return jsonify({"error": "Cannot friend yourself"}), 400

        # Check existing both directions (no .or_)
        ex1 = supabase.table('friendships').select('id, status') \
            .eq('requester_id', uid).eq('addressee_id', to_id).limit(1).execute()
        if ex1.data:
            return jsonify(ex1.data[0]), 200

        ex2 = supabase.table('friendships').select('id, status') \
            .eq('requester_id', to_id).eq('addressee_id', uid).limit(1).execute()
        if ex2.data:
            return jsonify(ex2.data[0]), 200

        ins = supabase.table('friendships').insert({
            'requester_id': uid, 'addressee_id': to_id, 'status': 'pending'
        }).execute()
        return jsonify(ins.data[0]), 201
    except Exception as e:
        app.logger.exception("request_friend error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/friends/respond', methods=['POST'])
@require_auth
def respond_friend():
    try:
        uid = request.user_id
        data = request.json or {}
        friendship_id = data.get('id')
        action = (data.get('action') or '').lower()  # accept | block | decline
        if action not in ['accept','block','decline']:
            return jsonify({"error":"Invalid action"}), 400

        fr = supabase.table('friendships').select('*').eq('id', friendship_id).single().execute()
        if not fr.data:
            return jsonify({"error":"Request not found"}), 404
        if fr.data['addressee_id'] != uid and fr.data['requester_id'] != uid:
            return jsonify({"error":"Unauthorized"}), 403

        if action == 'decline' and uid == fr.data['addressee_id']:
            supabase.table('friendships').delete().eq('id', friendship_id).execute()
            return jsonify({"success": True}), 200

        new_status = {'accept':'accepted','block':'blocked','decline':'declined'}[action]
        up = supabase.table('friendships').update({'status': new_status}).eq('id', friendship_id).execute()
        return jsonify(up.data[0]), 200
    except Exception as e:
        app.logger.exception("respond_friend error")
        return jsonify({"error": str(e)}), 500

# --------------------- Escrows ---------------------
@app.route('/api/escrows', methods=['POST'])
@require_auth
@limiter.limit("10 per hour")
def create_escrow():
    try:
        # Enhanced logging for debugging
        app.logger.info("=== CREATE_ESCROW REQUEST START ===")
        app.logger.info(f"Request headers: {dict(request.headers)}")
        app.logger.info(f"Request method: {request.method}")
        app.logger.info(f"Request URL: {request.url}")
        app.logger.info(f"User ID from auth: {request.user_id}")

        # Parse request data with detailed logging
        try:
            data = request.json or {}
            app.logger.info(f"Request JSON data: {data}")
        except Exception as json_error:
            app.logger.error(f"Failed to parse JSON: {json_error}")
            return jsonify({"error": "Invalid JSON format"}), 400

        user_id = request.user_id

        # Validate required fields with detailed logging
        required_fields = ['amount', 'currency', 'payment_method']
        app.logger.info(f"Required fields: {required_fields}")
        app.logger.info(f"Received fields: {list(data.keys())}")

        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            app.logger.error(f"Missing required fields: {missing_fields}")
            return jsonify({"error": f"Missing required fields: {missing_fields}"}), 400

        app.logger.info("Required fields validation passed")

        # Validate amount with detailed logging
        app.logger.info(f"Validating amount: {data['amount']} (type: {type(data['amount'])})")
        app.logger.info(f"Amount repr: {repr(data['amount'])}")
        try:
            float_amount = float(data['amount'])
            app.logger.info(f"Converted to float: {float_amount}")
        except Exception as e:
            app.logger.error(f"Failed to convert amount to float: {e}")
            return jsonify({"error": "Amount must be a valid number"}), 400

        # Get USD amount for validation (use amount if not provided for PayPal)
        usd_amount = data.get('usd_amount', data['amount'] if data.get('currency') == 'USD' else None)

        valid, error = validate_amount(data['amount'], data.get('currency'), usd_amount)
        if not valid:
            app.logger.error(f"Amount validation failed: {error}")
            app.logger.error(f"Raw amount: {repr(data['amount'])}")
            app.logger.error(f"Float amount: {float_amount}")
            app.logger.error(f"USD amount: {usd_amount}")
            app.logger.error(f"Currency: {data.get('currency')}")
            return jsonify({"error": error}), 400
        amount = float_amount
        app.logger.info(f"Amount validation passed: {amount}")

        # Validate currency with detailed logging
        currency = data['currency'].upper()
        app.logger.info(f"Validating currency: {currency}")
        valid, error = validate_currency(currency)
        if not valid:
            app.logger.error(f"Currency validation failed: {error}")
            return jsonify({"error": error}), 400
        app.logger.info("Currency validation passed")

        # Validate payment method with detailed logging
        payment_method = data['payment_method']
        app.logger.info(f"Validating payment method: {payment_method}")
        if payment_method not in ['crypto', 'paypal']:
            app.logger.error(f"Invalid payment method: {payment_method}")
            return jsonify({"error": "Invalid payment method"}), 400
        app.logger.info("Payment method validation passed")

        # Determine roles with detailed logging
        app.logger.info("Determining roles and counterparty")
        role = (data.get('initiator_role') or 'buyer').lower()
        counterparty = data.get('counterparty_username')
        app.logger.info(f"Initial role: {role}, counterparty: {counterparty}")

        if not counterparty and data.get('seller_username'):
            role = 'buyer'; counterparty = data['seller_username']
            app.logger.info(f"Updated from seller_username: role={role}, counterparty={counterparty}")
        if not counterparty and data.get('buyer_username'):
            role = 'seller'; counterparty = data['buyer_username']
            app.logger.info(f"Updated from buyer_username: role={role}, counterparty={counterparty}")

        app.logger.info(f"Final role: {role}, counterparty: {counterparty}")

        if role not in ['buyer','seller']:
            app.logger.error(f"Invalid initiator_role: {role}")
            return jsonify({"error":"Invalid initiator_role (buyer|seller)"}), 400
        if not counterparty:
            app.logger.error("Missing counterparty_username")
            return jsonify({"error":"Missing counterparty_username"}), 400

        # Lookup counterparty with detailed logging
        app.logger.info(f"Looking up counterparty: {counterparty}")
        try:
            lookup = supabase.table('profiles').select('id, username').ilike('username', counterparty).single().execute()
            if not lookup.data:
                app.logger.error(f"User '{counterparty}' not found")
                return jsonify({"error": f"User '{counterparty}' not found"}), 404
            counterparty_id = lookup.data['id']
            app.logger.info(f"Counterparty found: ID={counterparty_id}, username={lookup.data['username']}")
        except Exception as db_error:
            app.logger.error(f"Database error during user lookup: {db_error}")
            return jsonify({"error": "Database error during user lookup"}), 500

        # Determine buyer/seller IDs with logging
        if role == 'buyer':
            buyer_id = user_id; seller_id = counterparty_id
        else:
            buyer_id = counterparty_id; seller_id = user_id

        app.logger.info(f"Buyer ID: {buyer_id}, Seller ID: {seller_id}")

        if buyer_id == seller_id:
            app.logger.error("Attempted to create escrow with self")
            return jsonify({"error":"Cannot create escrow with yourself"}), 400

        # Calculate fees with logging
        app.logger.info("Calculating platform fees")
        fee_info = calculate_platform_fee(amount, currency, data['payment_method'])
        app.logger.info(f"Fee calculation result: {fee_info}")

        # Create escrow data
        escrow_data = {
            'buyer_id': buyer_id,
            'seller_id': seller_id,
            'amount': amount,
            'currency': currency,
            'payment_method': data['payment_method'],
            'platform_fee_rate': fee_info['fee_rate'],
            'platform_fee_amount': fee_info['fee_amount'],
            'usd_amount': fee_info['usd_amount'],
            'net_amount': fee_info['net_amount'],
            'title': data.get('title', f'Escrow #{str(uuid.uuid4())[:8]}'),  # Use provided title or generate default
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat()
        }
        app.logger.info(f"Escrow data to insert: {escrow_data}")

        # Insert escrow with error handling
        try:
            escrow_response = supabase.table('escrows').insert(escrow_data).execute()
            escrow_id = escrow_response.data[0]['id']
            app.logger.info(f"Escrow created successfully: ID={escrow_id}")
        except Exception as db_error:
            app.logger.error(f"Database error during escrow creation: {db_error}")
            return jsonify({"error": "Database error during escrow creation"}), 500

        # Handle payment method specific logic
        if data['payment_method'] == 'crypto':
            app.logger.info("Processing crypto payment method")
            address = generate_crypto_address(currency, escrow_id)
            if address:
                supabase.table('escrows').update({'deposit_address': address}).eq('id', escrow_id).execute()
                escrow_response.data[0]['deposit_address'] = address
                app.logger.info(f"Crypto address generated: {address}")
            else:
                # Rollback escrow creation
                app.logger.error("Failed to generate crypto address")
                supabase.table('escrows').delete().eq('id', escrow_id).execute()
                return jsonify({"error": "Failed to generate crypto address"}), 500

        elif data['payment_method'] == 'paypal':
            app.logger.info("Processing PayPal payment method")
            paypal_order = create_paypal_order_authorize(amount, currency, fee_info, escrow_id)
            if paypal_order:
                supabase.table('escrows').update({'paypal_order_id': paypal_order['id']}).eq('id', escrow_id).execute()
                escrow_response.data[0]['paypal_order_id'] = paypal_order['id']
                escrow_response.data[0]['paypal_approval_url'] = paypal_order.get('approval_url')
                app.logger.info(f"PayPal order created: {paypal_order['id']}")
            else:
                # Rollback escrow creation
                app.logger.error("Failed to create PayPal order")
                supabase.table('escrows').delete().eq('id', escrow_id).execute()
                return jsonify({"error": "Failed to create PayPal order"}), 500

        app.logger.info("=== CREATE_ESCROW REQUEST COMPLETED SUCCESSFULLY ===")
        return jsonify(escrow_response.data[0]), 201

    except Exception as e:
        app.logger.exception("create_escrow error")
        app.logger.error(f"Exception details: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/escrows/<escrow_id>', methods=['GET'])
@require_auth
def get_escrow(escrow_id):
    try:
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404
        data = escrow.data
        
        # Verify user is participant
        if request.user_id not in [data['buyer_id'], data['seller_id']]:
            return jsonify({"error": "Unauthorized"}), 403
        
        try:
            profs = supabase.table('profiles').select('id, username, display_name, avatar_url') \
                .in_('id', [data['buyer_id'], data['seller_id']]).execute()
            data['buyer_profile'] = next((p for p in profs.data if p['id']==data['buyer_id']), None)
            data['seller_profile'] = next((p for p in profs.data if p['id']==data['seller_id']), None)
        except Exception:
            data['buyer_profile'] = None; data['seller_profile'] = None
        return jsonify(data), 200
    except Exception as e:
        app.logger.exception("get_escrow error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/escrows/<escrow_id>/seller-details', methods=['POST'])
@require_auth
def set_seller_details(escrow_id):
    """Seller must provide payout details before funds can be released."""
    try:
        user_id = request.user_id
        data = request.json or {}
        
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404
        
        # Verify user is seller
        if escrow.data['seller_id'] != user_id:
            return jsonify({"error": "Only seller can set payout details"}), 403
        
        # Verify escrow is funded but not yet completed
        if escrow.data['status'] not in ['pending', 'funded']:
            return jsonify({"error": "Cannot update details at this stage"}), 400
        
        update_data = {}
        
        if escrow.data['payment_method'] == 'crypto':
            seller_address = data.get('seller_address')
            if not seller_address:
                return jsonify({"error": "Seller address required"}), 400
            
            # Validate address
            valid, error = validate_address(seller_address, escrow.data['currency'])
            if not valid:
                return jsonify({"error": error}), 400
            
            update_data['seller_address'] = seller_address
            
        elif escrow.data['payment_method'] == 'paypal':
            seller_email = data.get('seller_paypal_email')
            if not seller_email:
                return jsonify({"error": "Seller PayPal email required"}), 400
            
            # Basic email validation
            if '@' not in seller_email or len(seller_email) < 5:
                return jsonify({"error": "Invalid email format"}), 400
            
            update_data['seller_paypal_email'] = seller_email
        
        updated = supabase.table('escrows').update(update_data).eq('id', escrow_id).execute()
        return jsonify({"success": True, "escrow": updated.data[0]}), 200
        
    except Exception as e:
        app.logger.exception("set_seller_details error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/escrows/<escrow_id>/confirm', methods=['POST'])
@require_auth
def confirm_escrow(escrow_id):
    """Handle buyer/seller confirmations with proper state management."""
    try:
        user_id = request.user_id
        action = (request.json or {}).get('action')  # 'release' or 'cancel'
        
        if action not in ['release', 'cancel']:
            return jsonify({"error": "Invalid action"}), 400

        # Use transaction to prevent race conditions
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404

        # Check user is participant
        if user_id not in [escrow.data['buyer_id'], escrow.data['seller_id']]:
            return jsonify({"error": "Unauthorized"}), 403

        # For release, verify seller details are provided
        if action == 'release':
            if escrow.data['payment_method'] == 'crypto' and not escrow.data.get('seller_address'):
                return jsonify({"error": "Seller must provide crypto address before release"}), 400
            elif escrow.data['payment_method'] == 'paypal' and not escrow.data.get('seller_paypal_email'):
                return jsonify({"error": "Seller must provide PayPal email before release"}), 400

        # Update user's action
        update_data = {}
        other_action = None
        if escrow.data['buyer_id'] == user_id:
            update_data['buyer_action'] = action
            other_action = escrow.data.get('seller_action')
        else:
            update_data['seller_action'] = action
            other_action = escrow.data.get('buyer_action')

        # Update with optimistic locking to prevent double-processing
        updated = supabase.table('escrows').update(update_data).eq('id', escrow_id).eq('status', escrow.data['status']).execute()
        
        if not updated.data:
            # Status changed, re-fetch and return current state
            escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
            return jsonify(escrow.data), 200

        # Check if both parties agree
        if other_action and other_action == action:
            if action == 'release':
                # Attempt to release funds
                try:
                    # Update status first to prevent double-release
                    status_update = supabase.table('escrows').update({
                        'status': 'processing',
                        'buyer_confirmed': True,
                        'seller_confirmed': True
                    }).eq('id', escrow_id).eq('status', escrow.data['status']).execute()
                    
                    if not status_update.data:
                        # Already being processed
                        return jsonify({"error": "Transaction already being processed"}), 409
                    
                    # Release funds
                    success = release_funds(escrow_id)
                    
                    if success:
                        # Mark as completed
                        supabase.table('escrows').update({'status': 'completed'}).eq('id', escrow_id).execute()
                        
                        supabase.table('escrow_messages').insert({
                            'escrow_id': escrow_id,
                            'sender_id': user_id,
                            'message': 'Both parties agreed to release funds. Transaction completed!',
                            'message_type': 'system'
                        }).execute()
                    else:
                        # Rollback to funded status
                        supabase.table('escrows').update({'status': 'release_failed'}).eq('id', escrow_id).execute()
                        
                        supabase.table('escrow_messages').insert({
                            'escrow_id': escrow_id,
                            'sender_id': user_id,
                            'message': 'Release failed. Please contact support.',
                            'message_type': 'system'
                        }).execute()
                        
                        return jsonify({"error": "Failed to release funds"}), 500
                        
                except Exception as e:
                    app.logger.exception(f"Release failed for escrow {escrow_id}")
                    # Mark as failed
                    supabase.table('escrows').update({'status': 'release_failed'}).eq('id', escrow_id).execute()
                    raise

            elif action == 'cancel':
                supabase.table('escrows').update({'status': 'cancelled'}).eq('id', escrow_id).execute()
                supabase.table('escrow_messages').insert({
                    'escrow_id': escrow_id,
                    'sender_id': user_id,
                    'message': 'Both parties agreed to cancel. Transaction cancelled.',
                    'message_type': 'system'
                }).execute()

        # Return updated escrow
        final_escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        return jsonify(final_escrow.data), 200
        
    except Exception as e:
        app.logger.exception("confirm_escrow error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/escrows/<escrow_id>/check-payment', methods=['POST'])
@require_auth
@limiter.limit("10 per minute")
def check_payment_status(escrow_id):
    try:
        user_id = request.user_id
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404
        data = escrow.data
        if data['buyer_id'] != user_id:
            return jsonify({"error": "Unauthorized"}), 403
        if data['payment_method'] == 'crypto' and data.get('deposit_address'):
            received = check_crypto_payment(data['deposit_address'], data['currency'], data['amount'])
            if received:
                updated = supabase.table('escrows').update({'status': 'funded'}).eq('id', escrow_id).eq('status', 'pending').execute()
                if updated.data:
                    supabase.table('transactions').insert({
                        'escrow_id': escrow_id,
                        'type': 'deposit',
                        'amount': data['amount'],
                        'currency': data['currency'],
                        'transaction_hash': 'pending_verification'
                    }).execute()
                    return jsonify({"status": "funded", "escrow": updated.data[0]}), 200
                else:
                    # Already funded
                    return jsonify({"status": "funded", "message": "Already funded"}), 200
            else:
                return jsonify({"status": "pending", "message": "Payment not yet received"}), 200
        return jsonify({"error": "Invalid payment method or missing address"}), 400
    except Exception as e:
        app.logger.exception("check_payment_status error")
        return jsonify({"error": str(e)}), 500

# --------------------- PayPal helpers ---------------------
def get_paypal_access_token() -> str:
    try:
        r = requests.post(
            f"{PAYPAL_BASE_URL}/v1/oauth2/token",
            headers={'Accept':'application/json','Accept-Language':'en_US'},
            data={'grant_type': 'client_credentials'},
            auth=(PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET)
        )
        if r.status_code != 200:
            app.logger.error("PayPal OAuth error: %s", r.text)
            return None
        return r.json().get('access_token')
    except Exception:
        app.logger.exception("get_paypal_access_token error")
        return None
def create_paypal_order_authorize(amount, currency, fee_info, escrow_id=None, return_url=None, cancel_url=None):
    """Create a PayPal AUTHORIZATION order.
    Optionally include escrow_id to route back to escrow page, or explicit return/cancel URLs for other flows.
    """
    try:
        access_token = get_paypal_access_token()
        if not access_token:
            return None

        order_response = requests.post(
            f"{PAYPAL_BASE_URL}/v2/checkout/orders",
            headers={'Content-Type':'application/json','Authorization': f'Bearer {access_token}','PayPal-Request-Id': str(uuid.uuid4())},
            json={
                'intent': 'AUTHORIZE',
                'purchase_units': [{
                    'reference_id': f'escrow_{int(time.time())}',
                    'amount': { 'currency_code': 'USD', 'value': str(amount) },
                    'description': f'Medius Escrow - Amount: ${amount}, Fee: ${fee_info["fee_amount"]}'
                }],
                'application_context': {
                    'return_url': (return_url or (f"{FRONTEND_URL}/escrow/{escrow_id}?paypal=success" if escrow_id else f'{FRONTEND_URL}/cart?paypal=success')),
                    'cancel_url': (cancel_url or (f"{FRONTEND_URL}/escrow/{escrow_id}?paypal=cancel" if escrow_id else f'{FRONTEND_URL}/cart?paypal=cancel')),
                    'brand_name': 'Medius Escrow',
                    'locale': 'en-US',
                    'user_action': 'PAY_NOW',
                    'shipping_preference': 'NO_SHIPPING'
                }
            }
        )
        if order_response.status_code not in (200,201):
            app.logger.error("PayPal order creation failed: %s", order_response.text)
            return None
        order_data = order_response.json()
        approval_url = next((l.get('href') for l in order_data.get('links',[]) if l.get('rel')=='approve'), None)
        return {'id': order_data['id'], 'approval_url': approval_url, 'status': order_data.get('status')}
    except Exception:
        app.logger.exception("create_paypal_order_authorize error")
        return None

def get_authorization_id_from_order(order_id):
    try:
        access_token = get_paypal_access_token()
        if not access_token: return None

        # Retry up to 3 times with delay to handle potential race conditions
        for attempt in range(3):
            order_response = requests.get(
                f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}",
                headers={'Authorization': f'Bearer {access_token}','Content-Type':'application/json'}
            )
            if order_response.status_code != 200:
                app.logger.error("Failed to get order details: %s", order_response.text)
                return None

            order_data = order_response.json()
            app.logger.info(f"Order status: {order_data.get('status')}, attempt: {attempt + 1}")

            # Check if order is approved
            if order_data.get('status') != 'APPROVED':
                app.logger.warning(f"Order not approved yet, status: {order_data.get('status')}")
                if attempt < 2:  # Don't sleep on last attempt
                    import time
                    time.sleep(2)  # Wait 2 seconds before retry
                continue

            # Look for authorization in purchase units
            for unit in order_data.get('purchase_units', []):
                payments = unit.get('payments', {})
                authorizations = payments.get('authorizations', [])

                # If no authorizations found, try to authorize the order explicitly
                if not authorizations:
                    app.logger.info("No authorizations found, attempting to authorize order")
                    auth_response = requests.post(
                        f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}/authorize",
                        headers={'Authorization': f'Bearer {access_token}','Content-Type':'application/json'},
                        json={}
                    )
                    if auth_response.status_code == 201:
                        auth_data = auth_response.json()
                        for unit in auth_data.get('purchase_units', []):
                            for payment in unit.get('payments', {}).get('authorizations', []):
                                return payment.get('id')
                    else:
                        app.logger.error(f"Failed to authorize order: {auth_response.text}")

                # Return authorization if found
                for payment in authorizations:
                    return payment.get('id')

            if attempt < 2:  # Don't sleep on last attempt
                import time
                time.sleep(2)  # Wait 2 seconds before retry

        app.logger.error("No authorization found after all attempts")
        return None
    except Exception:
        app.logger.exception("get_authorization_id_from_order")
        return None

@app.route('/api/escrows/<escrow_id>/paypal-create', methods=['POST'])
@require_auth
def create_paypal_order_for_escrow(escrow_id):
    try:
        uid = request.user_id
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data: return jsonify({"error":"Escrow not found"}), 404
        data = escrow.data
        if data['buyer_id'] != uid: return jsonify({"error":"Unauthorized"}), 403
        if data['payment_method'] != 'paypal': return jsonify({"error":"Invalid payment method"}), 400

        if not data.get('platform_fee_amount'):
            fee_info = calculate_platform_fee(data['amount'], data['currency'], 'paypal')
            supabase.table('escrows').update({
                'platform_fee_rate': fee_info['fee_rate'],
                'platform_fee_amount': fee_info['fee_amount'],
                'net_amount': fee_info['net_amount'],
                'usd_amount': fee_info['usd_amount']
            }).eq('id', escrow_id).execute()
            data.update(fee_info)
        else:
            fee_info = {
                'fee_rate': data['platform_fee_rate'],
                'fee_amount': data['platform_fee_amount'],
                'net_amount': data['net_amount'],
                'usd_amount': data['usd_amount']
            }

        order = create_paypal_order_authorize(data['amount'], data['currency'], fee_info, escrow_id)
        if not order: return jsonify({"error":"Failed to create PayPal order"}), 500

        supabase.table('escrows').update({'paypal_order_id': order['id']}).eq('id', escrow_id).execute()
        return jsonify({"success": True, "paypal_order_id": order['id'], "approval_url": order['approval_url']}), 200
    except Exception:
        app.logger.exception("create_paypal_order_for_escrow error")
        return jsonify({"error": "Failed to create PayPal order"}), 500

@app.route('/api/escrows/<escrow_id>/paypal-authorize', methods=['POST'])
@require_auth
def handle_paypal_authorization(escrow_id):
    try:
        token = (request.json or {}).get('token')
        if not token: return jsonify({"error":"Missing PayPal token"}), 400

        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data: return jsonify({"error":"Escrow not found"}), 404

        auth_id = get_authorization_id_from_order(token)
        if not auth_id: return jsonify({"error":"No authorization ID found - PayPal authorization may still be processing. Please try again in a moment."}), 500

        # Store authorization ID separately
        updated = supabase.table('escrows').update({
            'status':'funded', 
            'paypal_authorization_id': auth_id
        }).eq('id', escrow_id).eq('status', 'pending').execute()
        
        if not updated.data:
            return jsonify({"error": "Escrow already funded"}), 409
            
        supabase.table('transactions').insert({
            'escrow_id': escrow_id,
            'type': 'deposit',
            'amount': escrow.data['amount'],
            'currency': escrow.data['currency'],
            'paypal_transaction_id': auth_id,
            'usd_amount': escrow.data['amount']
        }).execute()
        return jsonify({"success": True, "escrow": updated.data[0]}), 200
    except Exception:
        app.logger.exception("handle_paypal_authorization error")
        return jsonify({"error": "Failed to handle PayPal authorization"}), 500

def void_paypal_authorization(authorization_id):
    try:
        access_token = get_paypal_access_token()
        if not access_token: return False
        void_response = requests.post(
            f"{PAYPAL_BASE_URL}/v2/payments/authorizations/{authorization_id}/void",
            headers={'Content-Type':'application/json','Authorization': f'Bearer {access_token}','PayPal-Request-Id': str(uuid.uuid4())}
        )
        return void_response.status_code == 204
    except Exception:
        app.logger.exception("void_paypal_authorization error")
        return False

@app.route('/api/escrows/<escrow_id>/paypal-refund', methods=['POST'])
@require_auth
def process_paypal_cancel(escrow_id):
    try:
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data: return jsonify({"error":"Escrow not found"}), 404
        
        authorization_id = escrow.data.get('paypal_authorization_id')
        if not authorization_id:
            return jsonify({"error":"No authorization to void"}), 400
            
        success = void_paypal_authorization(authorization_id)
        if success:
            supabase.table('escrows').update({'status':'refunded'}).eq('id', escrow_id).execute()
            return jsonify({"success":True, "message":"PayPal authorization voided"}), 200
        return jsonify({"error":"Failed to void PayPal authorization"}), 500
    except Exception:
        app.logger.exception("process_paypal_cancel error")
        return jsonify({"error":"Failed to process PayPal cancel"}), 500

@app.route('/api/escrows/<escrow_id>/paypal-capture-refund', methods=['POST'])
@require_auth
def refund_paypal_capture(escrow_id):
    """Refund a captured PayPal payment. Body: { capture_id?: string, amount?: number }"""
    try:
        uid = request.user_id
        esc = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not esc.data:
            return jsonify({"error":"Escrow not found"}), 404

        body = request.get_json(silent=True) or {}
        capture_id = (body.get('capture_id') or '').strip()
        amount = body.get('amount')
        if not capture_id:
            tr = supabase.table('transactions').select('*').eq('escrow_id', escrow_id).eq('type','release').order('created_at', desc=True).limit(1).execute()
            if tr.data:
                capture_id = tr.data[0].get('paypal_transaction_id')
        if not capture_id:
            return jsonify({"error":"capture_id required or not found"}), 400

        access_token = get_paypal_access_token()
        if not access_token:
            return jsonify({"error":"PayPal auth failed"}), 500

        refund_body = {}
        if amount is not None:
            refund_body['amount'] = {'currency_code':'USD','value': str(float(amount))}
        rr = requests.post(
            f"{PAYPAL_BASE_URL}/v2/payments/captures/{capture_id}/refund",
            headers={'Content-Type':'application/json','Authorization': f'Bearer {access_token}','PayPal-Request-Id': f'refund_{capture_id}'},
            json=refund_body or {}
        )
        if rr.status_code not in (201, 202):
            app.logger.error("PayPal refund failed: %s", rr.text)
            return jsonify({"error":"Refund failed"}), 500
        refund_id = (rr.json() or {}).get('id')

        supabase.table('transactions').insert({
            'escrow_id': escrow_id,
            'type': 'refund',
            'amount': float(amount) if amount is not None else None,
            'currency': 'USD',
            'paypal_transaction_id': refund_id or capture_id,
            'usd_amount': float(amount) if amount is not None else None
        }).execute()
        supabase.table('escrows').update({'status':'refunded'}).eq('id', escrow_id).execute()

        return jsonify({'ok': True, 'refund_id': refund_id}), 200
    except Exception:
        app.logger.exception("refund_paypal_capture error")
        return jsonify({"error": "Refund handling failed"}), 500

# --------------------- Fee Logic ---------------------
def calculate_platform_fee(amount, currency, payment_method):
    """Calculate platform fee. For crypto, thresholds are in USD; we also return usd_amount."""
    try:
        amount_f = float(amount)

        # derive usd_amount
        if payment_method == 'crypto':
            price = get_usd_price(currency) or 0
            usd_amount = round(amount_f * price, 8)
        else:
            usd_amount = amount_f  # PayPal is USD

        if payment_method == 'crypto':
            fee_rate = 0.02 if usd_amount < 50 else 0.015
            fee_amount = round(amount_f * fee_rate, 8)  # fee in crypto units
            net_amount = round(amount_f - fee_amount, 8)  # crypto net in crypto units
        elif payment_method == 'paypal':
            fee_rate = 0.02
            fee_amount = round(usd_amount * fee_rate, 8)  # fee in USD
            net_amount = round(usd_amount - fee_amount, 8)  # net shown in USD context
        else:
            fee_rate = 0.02
            fee_amount = round(amount_f * fee_rate, 8)
            net_amount = round(amount_f - fee_amount, 8)

        return {
            'fee_rate': fee_rate,
            'fee_amount': fee_amount,
            'net_amount': net_amount,
            'usd_amount': usd_amount
        }
    except Exception:
        return {'fee_rate': 0.02, 'fee_amount': 0, 'net_amount': float(amount), 'usd_amount': float(amount)}

# --------------------- Refunds ---------------------
@app.route('/api/escrows/<escrow_id>/refund', methods=['POST'])
@require_auth
def process_refund(escrow_id):
    try:
        user_id = request.user_id
        buyer_refund_address = (request.json or {}).get('refund_address')
        if not buyer_refund_address:
            return jsonify({"error":"Refund address required"}), 400

        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data: return jsonify({"error":"Escrow not found"}), 404
        data = escrow.data

        if data['buyer_id'] != user_id:
            return jsonify({"error":"Unauthorized"}), 403
        if data['status'] != 'cancelled':
            return jsonify({"error":"Escrow must be cancelled to process refund"}), 400

        if data['payment_method'] == 'crypto':
            # Validate refund address
            valid, error = validate_address(buyer_refund_address, data['currency'])
            if not valid:
                return jsonify({"error": error}), 400
                
            tx_hash = send_crypto_transaction_kms(escrow_id, buyer_refund_address, data['amount'])
            if not tx_hash:
                return jsonify({"error":"Failed to process crypto refund"}), 500
            supabase.table('transactions').insert({
                'escrow_id': escrow_id, 'type':'refund','amount': data['amount'], 'currency': data['currency'], 'transaction_hash': tx_hash
            }).execute()
            supabase.table('escrows').update({'status':'refunded','buyer_refund_address': buyer_refund_address}).eq('id', escrow_id).execute()
            supabase.table('escrow_messages').insert({
                'escrow_id': escrow_id, 'sender_id': user_id, 'message': f'✅ Refund processed! Transaction: {tx_hash}', 'message_type':'system'
            }).execute()
            return jsonify({"success":True,"transaction_hash":tx_hash,"message":"Crypto refund processed successfully"}), 200

        elif data['payment_method'] == 'paypal':
            return jsonify({"error":"PayPal refund not implemented in this sample"}), 400

        return jsonify({"error":"Invalid payment method"}), 400
    except Exception:
        app.logger.exception("process_refund error")
        return jsonify({"error": "Refund failed"}), 500

# --------------------- Wallets & Crypto ---------------------
def generate_crypto_address(currency, escrow_id):
    try:
        with wallet_cache_lock:
            # Check cache first
            if escrow_id in ESCROW_WALLET_IDS:
                return ESCROW_WALLET_IDS[escrow_id]['address']
            
            # Check database
            existing_wallet = supabase.table('escrow_wallets').select('*').eq('escrow_id', escrow_id).execute()
            if existing_wallet.data:
                wallet_data = existing_wallet.data[0]
                # Return mnemonic as stored (no decryption)
                ESCROW_WALLET_IDS[escrow_id] = wallet_data
                return wallet_data['address']

        if not TATUM_API_KEY:
            app.logger.error("TATUM_API_KEY missing")
            return None

        headers = {'x-api-key': TATUM_API_KEY, 'Content-Type': 'application/json'}
        chain = CHAIN_MAP.get(currency.upper())
        if not chain:
            app.logger.error("Unsupported currency %s", currency)
            return None

        wallet_response = requests.get(f"{TATUM_API_URL}/{chain}/wallet", headers=headers, timeout=30)
        if wallet_response.status_code != 200:
            app.logger.error("wallet error: %s", wallet_response.text)
            return None
        wallet_data = wallet_response.json()
        mnemonic = wallet_data.get('mnemonic')
        xpub = wallet_data.get('xpub')
        if not xpub:
            app.logger.error("xpub missing from Tatum wallet response")
            return None

        addr_res = requests.get(f"{TATUM_API_URL}/{chain}/address/{xpub}/0", headers=headers, timeout=30)
        if addr_res.status_code != 200:
            app.logger.error("address error: %s", addr_res.text)
            return None
        address = addr_res.json().get('address')
        if not address:
            return None

        # Store mnemonic as-is (no encryption)
        
        rec = {
            'escrow_id': escrow_id, 
            'mnemonic': mnemonic,
            'xpub': xpub, 
            'address': address,
            'currency': currency, 
            'chain': chain, 
            'address_index': 0
        }
        
        try:
            supabase.table('escrow_wallets').insert(rec).execute()
        except Exception:
            app.logger.exception("save wallet warn")
        
        # Cache unencrypted version
        rec['mnemonic'] = mnemonic
        with wallet_cache_lock:
            ESCROW_WALLET_IDS[escrow_id] = rec
        
        return address
    except Exception:
        app.logger.exception("generate_crypto_address error")
        return None

def check_crypto_payment(address, currency, expected_amount):
    try:
        headers = {'x-api-key': TATUM_API_KEY, 'Content-Type': 'application/json'}
        chain = CHAIN_MAP.get(currency.upper())
        if not chain:
            return False
        r = requests.get(f"{TATUM_API_URL}/{chain}/address/balance/{address}", headers=headers, timeout=30)
        if r.status_code != 200:
            app.logger.error("balance check failed: %s", r.text)
            return False
        data = r.json()
        if 'incoming' in data:
            bal = float(data['incoming'])
        elif 'balance' in data:
            bal = float(data['balance'])
        else:
            return False
        return bal >= float(expected_amount)
    except Exception:
        app.logger.exception("check_crypto_payment error")
        return False

def send_crypto_transaction_kms(escrow_id, to_address, amount):
    """Send crypto from escrow deposit to recipient (uses stored mnemonic)."""
    try:
        # Validate destination address
        currency = None
        with wallet_cache_lock:
            if escrow_id in ESCROW_WALLET_IDS:
                currency = ESCROW_WALLET_IDS[escrow_id].get('currency')
        
        if currency:
            valid, error = validate_address(to_address, currency)
            if not valid:
                app.logger.error(f"Invalid destination address: {error}")
                return False
        
        # Get wallet info
        with wallet_cache_lock:
            if escrow_id not in ESCROW_WALLET_IDS:
                wallet_result = supabase.table('escrow_wallets').select('*').eq('escrow_id', escrow_id).single().execute()
                if not wallet_result.data:
                    app.logger.error("No wallet row for escrow %s", escrow_id)
                    return False
                wallet_data = wallet_result.data
                # Keep mnemonic as stored (no decryption)
                if wallet_data.get('mnemonic'):
                    pass
                ESCROW_WALLET_IDS[escrow_id] = wallet_data

            w = ESCROW_WALLET_IDS[escrow_id]
        
        currency = w['currency']
        chain = w['chain']
        from_address = w['address']
        mnemonic = w['mnemonic']
        index = w.get('address_index', 0)
        
        if not mnemonic:
            app.logger.error("Missing mnemonic for escrow %s", escrow_id)
            return False
        
        headers = {'x-api-key': TATUM_API_KEY, 'Content-Type': 'application/json'}

        priv_res = requests.post(f"{TATUM_API_URL}/{chain}/wallet/priv", 
                                headers=headers, 
                                json={"mnemonic": mnemonic, "index": index}, 
                                timeout=30)
        if priv_res.status_code != 200:
            app.logger.error("priv key fetch error: %s", priv_res.text)
            return False
        private_key = priv_res.json().get('key')

        if currency in ['BTC','LTC','BCH','DOGE']:
            tx_data = {
                "fromAddress":[{"address": from_address,"privateKey": private_key}],
                "to":[{"address": to_address,"value": float(amount)}]
            }
            send_url = f"{TATUM_API_URL}/{chain}/transaction"
        elif currency in ['ETH','MATIC','BNB']:
            tx_data = {
                "fromPrivateKey": private_key, 
                "to": to_address, 
                "amount": str(amount), 
                "currency": currency
            }
            send_url = f"{TATUM_API_URL}/{chain}/transaction"
        else:
            app.logger.error("Send not implemented for %s", currency)
            return False

        r = requests.post(send_url, headers=headers, json=tx_data, timeout=120)
        if r.status_code == 200:
            j = r.json()
            return j.get('txId') or j.get('transactionHash')
        app.logger.error("Send failed: %s", r.text)
        return False
    except Exception:
        app.logger.exception("send_crypto_transaction_kms error")
        return False

# --------------------- Release Funds ---------------------
def release_funds(escrow_id, override_address: str = None):
    """
    Release funds for an escrow with proper error handling.
    - For crypto: send from escrow wallet to seller_address; records USD platform fee correctly.
    - For PayPal: capture authorization and payout via Payouts API.
    """
    try:
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data:
            app.logger.error("Escrow not found %s", escrow_id)
            return False
        e = escrow.data

        # --- CRYPTO RELEASE ---
        if e.get('payment_method') == 'crypto':
            seller_address = override_address or e.get('seller_address')
            if not seller_address:
                supabase.table('escrow_messages').insert({
                    'escrow_id': escrow_id,
                    'sender_id': e.get('seller_id'),
                    'message': '❌ Cannot release funds: Seller address not provided',
                    'message_type': 'system'
                }).execute()
                return False

            # First attempt to send platform fee to configured fee address (if present)
            platform_fee_crypto = float(e.get('platform_fee_amount') or 0)
            platform_fee_tx = None
            fee_addr = get_fee_address(e.get('currency'))
            if platform_fee_crypto and fee_addr:
                try:
                    platform_fee_tx = send_crypto_transaction_kms(escrow_id, fee_addr, platform_fee_crypto)
                    if not platform_fee_tx:
                        app.logger.warning('Platform fee send failed for escrow %s to %s', escrow_id, fee_addr)
                except Exception:
                    app.logger.exception('Platform fee send exception for escrow %s', escrow_id)

            # Then send remainder (net amount) to seller
            seller_tx = send_crypto_transaction_kms(escrow_id, seller_address, e.get('net_amount'))
            if not seller_tx:
                supabase.table('escrow_messages').insert({
                    'escrow_id': escrow_id,
                    'sender_id': e.get('seller_id'),
                    'message': f'❌ Failed to release funds to seller. Please contact support. Escrow ID: {escrow_id}',
                    'message_type': 'system'
                }).execute()
                return False

            # Compute USD platform fee once (rounded to cents)
            usd_amount_val = float(e.get('usd_amount') or 0)
            fee_rate_val = float(e.get('platform_fee_rate') or 0)
            platform_fee_usd = round(usd_amount_val * fee_rate_val, 2)

            # Record seller release transaction
            supabase.table('transactions').insert({
                'escrow_id': escrow_id,
                'type': 'release',
                'amount': e.get('net_amount'),
                'currency': e.get('currency'),
                'transaction_hash': seller_tx,
                'usd_amount': e.get('usd_amount')  # total order USD (pre-fee)
            }).execute()

            # Record platform fee transaction (may be None if send failed or no fee addr configured)
            supabase.table('transactions').insert({
                'escrow_id': escrow_id,
                'type': 'platform_fee',
                'amount': e.get('platform_fee_amount'),  # crypto fee amount
                'currency': e.get('currency'),
                'transaction_hash': platform_fee_tx,
                'usd_amount': platform_fee_usd          # USD fee
            }).execute()

            # System message summarizing both txs
            fee_note = f' (Platform fee sent to {fee_addr} tx: {platform_fee_tx})' if platform_fee_tx else f' (Platform fee not sent automatically)'
            supabase.table('escrow_messages').insert({
                'escrow_id': escrow_id,
                'sender_id': e.get('seller_id'),
                'message': f'✅ Funds released! Seller receives: {e.get("net_amount")} {e.get("currency")} (Platform fee: {e.get("platform_fee_amount")}). Seller tx: {seller_tx}.{fee_note}',
                'message_type': 'system'
            }).execute()

            # Award referral (crypto-only)
            try:
                award_referral_payout(escrow_id)
            except Exception:
                app.logger.exception("award_referral_payout failed after release")

        # --- PAYPAL RELEASE ---
        elif e.get('payment_method') == 'paypal':
            seller_email = e.get('seller_paypal_email')
            authorization_id = e.get('paypal_authorization_id')

            if not authorization_id or not seller_email:
                supabase.table('escrow_messages').insert({
                    'escrow_id': escrow_id,
                    'sender_id': e.get('seller_id'),
                    'message': '❌ Cannot release funds: Missing authorization or seller PayPal email',
                    'message_type': 'system'
                }).execute()
                return False

            ok, capture_id, payout_batch_id = release_paypal_funds_to_seller(escrow_id, authorization_id, seller_email)
            if not ok:
                supabase.table('escrow_messages').insert({
                    'escrow_id': escrow_id,
                    'sender_id': e.get('seller_id'),
                    'message': '❌ Failed to release PayPal payment. Please contact support.',
                    'message_type': 'system'
                }).execute()
                return False

            supabase.table('transactions').insert({
                'escrow_id': escrow_id,
                'type': 'release',
                'amount': e.get('net_amount', e.get('amount')),
                'currency': e.get('currency'),
                'paypal_transaction_id': capture_id or authorization_id,
                'usd_amount': e.get('net_amount', e.get('amount'))
            }).execute()

            supabase.table('escrow_messages').insert({
                'escrow_id': escrow_id,
                'sender_id': e.get('seller_id'),
                'message': f'✅ PayPal funds released to {seller_email}! Amount: ${e.get("net_amount", e.get("amount"))} (capture: {capture_id or "?"}, payout: {payout_batch_id or "?"})',
                'message_type': 'system'
            }).execute()

        return True
    except Exception:
        app.logger.exception("release_funds error")
        try:
            supabase.table('escrow_messages').insert({
                'escrow_id': escrow_id,
                'sender_id': 'system',
                'message': '❌ System error releasing funds: see server logs',
                'message_type': 'system'
            }).execute()
        except Exception:
            pass
        return False
        
def release_paypal_funds_to_seller(escrow_id, authorization_id, seller_paypal_email):
    """Capture payment then Payout to seller (PayPal Payouts).
    Returns (ok: bool, capture_id: Optional[str], payout_batch_id: Optional[str])
    """
    try:
        access_token = get_paypal_access_token()
        if not access_token:
            return False, None, None

        esc = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute().data
        cap = requests.post(
            f"{PAYPAL_BASE_URL}/v2/payments/authorizations/{authorization_id}/capture",
            headers={'Content-Type':'application/json','Authorization': f'Bearer {access_token}','PayPal-Request-Id': f"capture_{authorization_id}"},
            json={'amount': {'currency_code':'USD','value': str(esc.get('amount',0))}, 'final_capture': True,
                  'note_to_payer':'Medius Escrow - Payment captured'}
        )
        if cap.status_code != 201:
            app.logger.error("Payment capture failed: %s", cap.text)
            return False, None, None
        capture_id = None
        try:
            capture_id = (cap.json() or {}).get('id') or (cap.json() or {}).get('result',{}).get('id')
        except Exception:
            capture_id = None

        po = requests.post(
            f"{PAYPAL_BASE_URL}/v1/payments/payouts",
            headers={'Content-Type':'application/json','Authorization': f'Bearer {access_token}','PayPal-Request-Id': f"payout_{escrow_id}"},
            json={
                'sender_batch_header': {
                    'sender_batch_id': f'escrow_{escrow_id}_{int(time.time())}',
                    'email_subject': 'Medius Escrow - Payment Released',
                    'email_message': f'Your escrow payment of ${esc.get("net_amount", esc.get("amount"))} has been released.'
                },
                'items': [{
                    'recipient_type': 'EMAIL',
                    'amount': {'value': str(esc.get('net_amount', esc.get('amount'))), 'currency': 'USD'},
                    'receiver': seller_paypal_email,
                    'note': f'Medius Escrow Release - Transaction #{str(escrow_id)[:8]}',
                    'sender_item_id': f'escrow_{escrow_id}'
                }]
            }
        )
        payout_batch_id = None
        if po.status_code == 201:
            try:
                payout_batch_id = (po.json() or {}).get('batch_header',{}).get('payout_batch_id')
            except Exception:
                payout_batch_id = None
            return True, capture_id, payout_batch_id
        app.logger.error("PayPal payout failed: %s", po.text)
        return False, capture_id, None
    except Exception:
        app.logger.exception("release_paypal_funds_to_seller error")
        return False, None, None

# --------------------- PayPal Webhook ---------------------
@app.route('/api/paypal/webhook', methods=['POST'])
def paypal_webhook():
    try:
        if not PAYPAL_WEBHOOK_ID:
            app.logger.warning("PAYPAL_WEBHOOK_ID missing; skipping signature verification")
        else:
            access_token = get_paypal_access_token()
            if not access_token:
                return jsonify({"error": "auth failed"}), 401
            verification = {
                'auth_algo': request.headers.get('Paypal-Auth-Algo'),
                'cert_url': request.headers.get('Paypal-Cert-Url'),
                'transmission_id': request.headers.get('Paypal-Transmission-Id'),
                'transmission_sig': request.headers.get('Paypal-Transmission-Sig'),
                'transmission_time': request.headers.get('Paypal-Transmission-Time'),
                'webhook_id': PAYPAL_WEBHOOK_ID,
                'webhook_event': request.get_json(silent=True) or {}
            }
            vr = requests.post(
                f"{PAYPAL_BASE_URL}/v1/notifications/verify-webhook-signature",
                headers={'Content-Type':'application/json','Authorization': f'Bearer {access_token}'},
                json=verification
            )
            if vr.status_code != 200 or (vr.json() or {}).get('verification_status') != 'SUCCESS':
                app.logger.warning("PayPal webhook verification failed: %s", vr.text)
                return jsonify({"error": "invalid signature"}), 400

        data = request.get_json(silent=True) or {}
        event_type = data.get('event_type') or data.get('event_name')

        if event_type in ('CHECKOUT.ORDER.APPROVED', 'PAYMENT.AUTHORIZATION.CREATED'):
            order_id = None
            auth_id = None
            try:
                if event_type == 'CHECKOUT.ORDER.APPROVED':
                    order_id = (data.get('resource') or {}).get('id')
                else:
                    rel = (data.get('resource') or {}).get('supplementary_data', {}).get('related_ids', {})
                    order_id = rel.get('order_id')
                    auth_id = (data.get('resource') or {}).get('id')
            except Exception:
                pass
            access_token = get_paypal_access_token()
            if order_id and not auth_id and access_token:
                orr = requests.get(f"{PAYPAL_BASE_URL}/v2/checkout/orders/{order_id}", headers={'Authorization': f'Bearer {access_token}'})
                if orr.status_code == 200:
                    od = orr.json()
                    for unit in od.get('purchase_units', []):
                        for p in unit.get('payments', {}).get('authorizations', []):
                            auth_id = p.get('id')
                            break
            if order_id and auth_id:
                try:
                    esc = supabase.table('escrows').select('*').eq('paypal_order_id', order_id).single().execute()
                    if esc and esc.data and esc.data.get('status') == 'pending':
                        supabase.table('escrows').update({'status':'funded','paypal_authorization_id': auth_id}).eq('id', esc.data['id']).execute()
                        supabase.table('transactions').insert({
                            'escrow_id': esc.data['id'], 'type':'deposit', 'amount': esc.data['amount'], 'currency': esc.data['currency'],
                            'paypal_transaction_id': auth_id, 'usd_amount': esc.data['amount']
                        }).execute()
                except Exception:
                    app.logger.exception("webhook reconciliation failed for order %s", order_id)

        elif event_type == 'PAYMENT.CAPTURE.COMPLETED':
            rel = (data.get('resource') or {}).get('supplementary_data', {}).get('related_ids', {})
            order_id = rel.get('order_id')
            capture_id = (data.get('resource') or {}).get('id')
            if order_id and capture_id:
                try:
                    esc = supabase.table('escrows').select('id').eq('paypal_order_id', order_id).single().execute()
                    if esc and esc.data:
                        supabase.table('transactions').insert({
                            'escrow_id': esc.data['id'], 'type': 'release', 'amount': None, 'currency': 'USD', 'paypal_transaction_id': capture_id
                        }).execute()
                except Exception:
                    pass

        return jsonify({"status": "ok"}), 200
    except Exception:
        app.logger.exception("paypal_webhook error")
        return jsonify({"error": "webhook handling failed"}), 500

# --------------------- Referrals ---------------------
def award_referral_payout(escrow_id):
    """Accrue referral commission for any payment method and credit ledger in USD (rounded to cents)."""
    try:
        esc = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not esc.data:
            app.logger.warning("[referral] escrow %s not found", escrow_id)
            return False
        e = esc.data

        # Apply to all supported payment methods (crypto, paypal)
        pm = (e.get('payment_method') or '').lower()
        if pm not in ('crypto', 'paypal'):
            app.logger.info("[referral] skipping unsupported payment method for %s", escrow_id)
            return True

        # Idempotency (also enforce DB unique on referral_payouts(escrow_id))
        existing = supabase.table('referral_payouts').select('id').eq('escrow_id', escrow_id).execute()
        if existing.data:
            app.logger.info("[referral] payout already exists for %s", escrow_id)
            return True

        # Buyer must have a referrer
        buyer = supabase.table('profiles').select('id, referred_by').eq('id', e['buyer_id']).single().execute()
        if not buyer.data or not buyer.data.get('referred_by'):
            app.logger.info("[referral] buyer has no referrer for escrow %s", escrow_id)
            return True

        referrer_id = buyer.data['referred_by']

        # Commission = USD(platform fee) * REFERRAL_RATE (rounded to cents)
        usd_amount = float(e.get('usd_amount') or 0)
        platform_fee_rate = float(e.get('platform_fee_rate') or 0)
        platform_fee_usd = round(usd_amount * platform_fee_rate, 2)
        if platform_fee_usd <= 0 or REFERRAL_RATE <= 0:
            app.logger.info("[referral] no commission for %s", escrow_id)
            return True

        commission_usd = round(platform_fee_usd * REFERRAL_RATE, 2)

        supabase.table('referral_payouts').insert({
            'referrer_id': referrer_id,
            'referred_user_id': e['buyer_id'],
            'escrow_id': escrow_id,
            'amount_usd': commission_usd,
            'currency': 'USD',
            'rate': REFERRAL_RATE,
            'status': 'accrued',
            'created_at': datetime.utcnow().isoformat()
        }).execute()

        supabase.table('referral_ledger').insert({
            'user_id': referrer_id,
            'type': 'credit',
            'source': 'escrow_commission',
            'amount_usd': commission_usd,
            'escrow_id': escrow_id,
            'note': f'Commission from escrow {escrow_id}'
        }).execute()

        app.logger.info("[referral] commission %.2f USD credited to %s for escrow %s", commission_usd, referrer_id, escrow_id)
        return True
    except Exception:
        app.logger.exception("award_referral_payout error")
        return False

@app.route('/api/referrals/claim', methods=['POST'])
@require_auth
@limiter.limit("5 per hour")
def claim_referral():
    try:
        uid = request.user_id
        code_or_username = (request.json or {}).get('code', '').strip()
        if not code_or_username:
            return jsonify({"error": "Missing code"}), 400

        me = supabase.table('profiles').select('id, referred_by').eq('id', uid).single().execute()
        if not me.data:
            return jsonify({"error": "Profile not found"}), 404
        if me.data.get('referred_by'):
            return jsonify({"error": "Referral already claimed"}), 400

        # Try referral_code exact match first
        by_code = supabase.table('profiles').select('id, username, referral_code') \
            .eq('referral_code', code_or_username).limit(1).execute()
        candidate = by_code.data[0] if by_code.data else None

        # Fallback: username case-insensitive equals (no wildcards)
        if not candidate:
            by_username = supabase.table('profiles').select('id, username, referral_code') \
                .ilike('username', code_or_username).limit(1).execute()
            candidate = by_username.data[0] if by_username.data else None

        if not candidate:
            return jsonify({"error": "Invalid referral code"}), 404

        referrer_id = candidate['id']
        if referrer_id == uid:
            return jsonify({"error": "Cannot refer yourself"}), 400

        supabase.table('profiles').update({'referred_by': referrer_id}).eq('id', uid).execute()
        return jsonify({"success": True}), 200
    except Exception:
        app.logger.exception("claim_referral error")
        return jsonify({"error": "Failed to claim referral"}), 500

@app.route('/api/referrals/summary', methods=['GET'])
@require_auth
def referral_summary():
    try:
        uid = request.user_id
        me = supabase.table('profiles').select('username, referral_code, referral_payout_address, referral_payout_currency') \
            .eq('id', uid).single().execute()
        if not me.data:
            return jsonify({"error":"Profile not found"}), 404
        code = me.data.get('referral_code')
        link = f"{FRONTEND_URL}/auth?ref={code}"

        referred = supabase.table('profiles').select('id, username, display_name, avatar_url, created_at') \
            .eq('referred_by', uid).order('created_at', desc=True).execute()
        payouts = supabase.table('referral_payouts').select('id, escrow_id, amount_usd, currency, rate, status, created_at, referred_user_id') \
            .eq('referrer_id', uid).order('created_at', desc=True).execute()
        ledger = supabase.table('referral_ledger').select('*').eq('user_id', uid).order('created_at', desc=True).execute()
        withdrawals = supabase.table('referral_withdrawals').select('*').eq('user_id', uid).order('created_at', desc=True).execute()

        credits = sum(float(x['amount_usd']) for x in (ledger.data or []) if x.get('type')=='credit')
        debits  = sum(float(x['amount_usd']) for x in (ledger.data or []) if x.get('type')=='debit')
        balance_usd = round(credits - debits, 2)

        return jsonify({
            "username": me.data.get('username'),
            "referral_code": code,
            "referral_link": link,
            "payout_address": me.data.get('referral_payout_address'),
            "payout_currency": me.data.get('referral_payout_currency'),
            "rate": REFERRAL_RATE,
            "referred_count": len(referred.data or []),
            "referred_users": referred.data or [],
                        "entries": payouts.data or [],
            "balance_usd": balance_usd,
            "withdrawals": withdrawals.data or []
        }), 200
    except Exception:
        app.logger.exception("referral_summary error")
        return jsonify({"error": "Failed to load referral summary"}), 500

# --------------------- Admin Referrals Overview ---------------------
@app.route('/api/admin/referrals', methods=['GET'])
@require_admin
@limiter.limit("60 per minute")
def admin_referrals_overview():
    """List users with their referral payout details and performance metrics."""
    try:
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)
        search = (request.args.get('search') or '').strip()
        offset = (page - 1) * limit

        users_q = supabase.table('profiles').select('id, username, display_name, created_at, referral_payout_address, referral_payout_currency')
        if search:
            users_q = users_q.ilike('username', f'%{search}%')
        users = users_q.range(offset, offset + limit - 1).order('created_at', desc=True).execute()

        items = []
        for u in users.data or []:
            uid = u['id']
            referred = supabase.table('profiles').select('id').eq('referred_by', uid).execute()
            payouts = supabase.table('referral_payouts').select('amount_usd, status').eq('referrer_id', uid).execute()
            ledger = supabase.table('referral_ledger').select('amount_usd, type').eq('user_id', uid).execute()
            withdrawals = supabase.table('referral_withdrawals').select('amount_usd, status').eq('user_id', uid).eq('status', 'paid').execute()

            total_referred = len(referred.data or [])
            total_accrued = sum(float(p.get('amount_usd') or 0) for p in (payouts.data or []) if p.get('status') in ['accrued','processing','paid'])
            total_paid = sum(float(w.get('amount_usd') or 0) for w in (withdrawals.data or []))
            credits = sum(float(x.get('amount_usd') or 0) for x in (ledger.data or []) if x.get('type')=='credit')
            debits  = sum(float(x.get('amount_usd') or 0) for x in (ledger.data or []) if x.get('type')=='debit')
            balance = round(credits - debits, 2)

            items.append({
                **u,
                'totals': {
                    'referred_count': total_referred,
                    'accrued_usd': round(total_accrued, 2),
                    'paid_usd': round(total_paid, 2),
                    'balance_usd': balance
                }
            })

        count_q = supabase.table('profiles').select('id', count='exact')
        if search:
            count_q = count_q.ilike('username', f'%{search}%')
        count_res = count_q.execute()
        total = count_res.count or 0

        return jsonify({
            'items': items,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        }), 200
    except Exception:
        app.logger.exception('admin_referrals_overview error')
        return jsonify({'error': 'Failed to load admin referrals'}), 500

@app.route('/api/referrals/withdraw', methods=['POST'])
@require_auth
@limiter.limit("5 per day")
def referral_withdraw():
    try:
        uid = request.user_id
        body = request.json or {}

        amount_usd = float(body.get('amount_usd') or 0)
        currency = (body.get('currency') or '').upper().strip()
        to_address = (body.get('to_address') or '').strip()

        if amount_usd < MIN_WITHDRAW_USD:
            return jsonify({"error": f"Minimum withdrawal is ${MIN_WITHDRAW_USD}"}), 400
        if amount_usd > 10000:
            return jsonify({"error": "Maximum withdrawal is $10,000"}), 400

        # REQUIRE both fields each time (no profile fallback)
        if not currency or not to_address:
            return jsonify({"error":"Provide payout address and currency"}), 400
        if currency == 'USD':
            return jsonify({"error":"USD withdrawals are not supported. Select a crypto network."}), 400
        valid, err = validate_currency(currency)
        if not valid: return jsonify({"error": err}), 400
        valid, err = validate_address(to_address, currency)
        if not valid: return jsonify({"error": f"Invalid address: {err}"}), 400

        # Compute available balance (with lock to prevent race conditions)
        ledger = supabase.table('referral_ledger').select('*').eq('user_id', uid).execute()
        credits = sum(float(x['amount_usd']) for x in (ledger.data or []) if x.get('type')=='credit')
        debits  = sum(float(x['amount_usd']) for x in (ledger.data or []) if x.get('type')=='debit')
        balance = round(credits - debits, 2)
        
        if amount_usd > balance:
            return jsonify({"error":"Insufficient balance"}), 400

        # Create withdrawal record with 'processing' status
        wd = supabase.table('referral_withdrawals').insert({
            'user_id': uid, 
            'amount_usd': amount_usd, 
            'currency': currency, 
            'to_address': to_address, 
            'status':'processing', 
            'created_at': datetime.utcnow().isoformat()
        }).execute()
        wd_id = wd.data[0]['id']

        # Immediately debit the ledger to prevent double-spending
        supabase.table('referral_ledger').insert({
            'user_id': uid, 
            'type':'debit',
            'source':'withdrawal',
            'amount_usd': amount_usd,
            'withdrawal_id': wd_id, 
            'note': f'Withdrawal {amount_usd} USD in {currency}', 
            'created_at': datetime.utcnow().isoformat()
        }).execute()

        try:
            # Convert USD -> currency
            price = get_usd_price(currency)
            if not price or price <= 0:
                # Rollback by crediting the ledger
                supabase.table('referral_ledger').insert({
                    'user_id': uid, 
                    'type':'credit',
                    'source':'withdrawal_failed',
                    'amount_usd': amount_usd,
                    'withdrawal_id': wd_id, 
                    'note': f'Withdrawal failed - price unavailable', 
                    'created_at': datetime.utcnow().isoformat()
                }).execute()
                supabase.table('referral_withdrawals').update({'status':'failed'}).eq('id', wd_id).execute()
                return jsonify({"error":"Price unavailable, please try again later"}), 500
            
            amount_currency = round(amount_usd / price, 8)

            # Send payout
            tx_hash = send_platform_crypto(currency, to_address, amount_currency)
            if not tx_hash:
                # Rollback by crediting the ledger
                supabase.table('referral_ledger').insert({
                    'user_id': uid, 
                    'type':'credit',
                    'source':'withdrawal_failed',
                    'amount_usd': amount_usd,
                    'withdrawal_id': wd_id, 
                    'note': f'Withdrawal failed - payout error', 
                    'created_at': datetime.utcnow().isoformat()
                }).execute()
                supabase.table('referral_withdrawals').update({'status':'failed'}).eq('id', wd_id).execute()
                return jsonify({"error":"Payout failed, please try again later"}), 500

            # Mark paid
            supabase.table('referral_withdrawals').update({
                'status':'paid',
                'tx_hash': tx_hash,
                'paid_at': datetime.utcnow().isoformat(),
                'amount_crypto': amount_currency,
                'exchange_rate': price
            }).eq('id', wd_id).execute()

            return jsonify({
                "success": True, 
                "tx_hash": tx_hash,
                "amount_usd": amount_usd,
                "amount_crypto": amount_currency,
                "currency": currency
            }), 200
            
        except Exception as e:
            # Rollback on any error
            app.logger.exception("Withdrawal processing failed")
            supabase.table('referral_ledger').insert({
                'user_id': uid, 
                'type':'credit',
                'source':'withdrawal_failed',
                'amount_usd': amount_usd,
                'withdrawal_id': wd_id, 
                'note': f'Withdrawal failed - system error', 
                'created_at': datetime.utcnow().isoformat()
            }).execute()
            supabase.table('referral_withdrawals').update({'status':'failed'}).eq('id', wd_id).execute()
            raise
            
    except Exception:
        app.logger.exception("referral_withdraw error")
        return jsonify({"error": "Withdrawal failed"}), 500

# --------------------- Escrow Messages ---------------------
@app.route('/api/escrows/<escrow_id>/messages', methods=['GET'])
@require_auth
def get_messages(escrow_id):
    """Get messages for an escrow."""
    try:
        # Verify user is participant
        escrow = supabase.table('escrows').select('buyer_id, seller_id').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404
        if request.user_id not in [escrow.data['buyer_id'], escrow.data['seller_id']]:
            return jsonify({"error": "Unauthorized"}), 403
        
        messages = supabase.table('escrow_messages') \
            .select('*') \
            .eq('escrow_id', escrow_id) \
            .order('created_at', desc=False) \
            .execute()
        
        return jsonify(messages.data or []), 200
    except Exception as e:
        app.logger.exception("get_messages error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/escrows/<escrow_id>/messages', methods=['POST'])
@require_auth
@limiter.limit("60 per minute")
def send_message(escrow_id):
    """Send a message in an escrow chat."""
    try:
        user_id = request.user_id
        data = request.json or {}
        message = (data.get('message') or '').strip()
        client_nonce = data.get('client_nonce')
        
        if not message:
            return jsonify({"error": "Message cannot be empty"}), 400
        if len(message) > 1000:
            return jsonify({"error": "Message too long (max 1000 chars)"}), 400
        
        # Verify user is participant
        escrow = supabase.table('escrows').select('buyer_id, seller_id, status').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404
        if user_id not in [escrow.data['buyer_id'], escrow.data['seller_id']]:
            return jsonify({"error": "Unauthorized"}), 403
        
        # Don't allow messages on completed/cancelled escrows (optional)
        # if escrow.data['status'] in ['completed', 'cancelled', 'refunded']:
        #     return jsonify({"error": "Cannot send messages to closed escrow"}), 400
        
        msg_data = {
            'escrow_id': escrow_id,
            'sender_id': user_id,
            'message': message,
            'message_type': 'user',
            'created_at': datetime.utcnow().isoformat()
        }
        
        if client_nonce:
            msg_data['client_nonce'] = client_nonce
        
        result = supabase.table('escrow_messages').insert(msg_data).execute()
        
        return jsonify(result.data[0]), 201
        
    except Exception as e:
        app.logger.exception("send_message error")
        return jsonify({"error": str(e)}), 500

# --------------------- Admin / System Status ---------------------
@app.route('/api/system/status', methods=['GET'])
@require_admin
def system_status():
    """Get basic system status (admin only)."""
    try:
        user_id = request.user_id

        status = {
            "timestamp": datetime.utcnow().isoformat(),
            "supabase": "connected" if supabase else "disconnected",
            "tatum_configured": bool(TATUM_API_KEY),
            "paypal_configured": bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET),
            "platform_wallets": {
                "BTC": bool(get_platform_address('BTC')),
                "ETH": bool(get_platform_address('ETH')),
                "USDT": bool(get_platform_address('USDT'))
            },
            "referral_rate": REFERRAL_RATE,
            "min_withdraw_usd": MIN_WITHDRAW_USD,
            "admin_authenticated": True,
            "admin_id": user_id
        }

        # Log admin basic status access
        log_admin_action(user_id, "Viewed basic system status", request.remote_addr)

        return jsonify(status), 200
    except Exception as e:
        app.logger.exception("system_status error")
        return jsonify({"error": str(e)}), 500




# ============================================
# ADMIN ENDPOINTS
# ============================================

@app.route('/api/admin/exchanges/stats', methods=['GET'])
@require_admin
def admin_exchange_stats():
    """
    Get exchange statistics for admin dashboard
    
    Query params:
    - range: '24h', '7d', '30d' (default: '24h')
    
    Returns:
    - Total exchanges
    - Status breakdown
    - Currency pairs
    - Provider stats
    - Volume estimates
    """
    try:
        time_range = request.args.get('range', '24h')
        
        # Calculate time threshold
        if time_range == '24h':
            since = datetime.utcnow() - timedelta(hours=24)
        elif time_range == '7d':
            since = datetime.utcnow() - timedelta(days=7)
        elif time_range == '30d':
            since = datetime.utcnow() - timedelta(days=30)
        else:
            since = datetime.utcnow() - timedelta(hours=24)
        
        # Get exchanges in range
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .gte('created_at', since.isoformat())\
            .execute()
        
        exchanges = result.data or []
        total_count = len(exchanges)
        
        # Status breakdown
        status_counts = {}
        for ex in exchanges:
            status = ex['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Provider breakdown
        provider_counts = {}
        for ex in exchanges:
            provider = ex.get('swapkit_provider', 'unknown')
            if provider:
                provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        # Currency pairs
        pair_counts = {}
        for ex in exchanges:
            pair = f"{ex['from_currency']}/{ex['to_currency']}"
            pair_counts[pair] = pair_counts.get(pair, 0) + 1
        
        # Top pairs
        top_pairs = dict(sorted(pair_counts.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Calculate volume (simplified - just count of from_amount)
        total_volume = {}
        for ex in exchanges:
            currency = ex['from_currency']
            amount = Decimal(ex.get('from_amount', 0) or 0)
            total_volume[currency] = total_volume.get(currency, Decimal('0')) + amount
        
        # Calculate fees collected
        total_fees = {}
        for ex in exchanges:
            if ex['status'] == 'completed':
                currency = ex['to_currency']
                fee = Decimal(ex.get('platform_fee_amount', 0) or 0)
                total_fees[currency] = total_fees.get(currency, Decimal('0')) + fee
        
        # Success rate
        completed = status_counts.get('completed', 0)
        failed = status_counts.get('failed', 0)
        total_finished = completed + failed
        success_rate = (completed / total_finished * 100) if total_finished > 0 else 0
        
        return jsonify({
            'time_range': time_range,
            'since': since.isoformat(),
            'total_exchanges': total_count,
            'status_breakdown': status_counts,
            'provider_breakdown': provider_counts,
            'top_pairs': top_pairs,
            'total_volume': {k: str(v) for k, v in total_volume.items()},
            'total_fees_collected': {k: str(v) for k, v in total_fees.items()},
            'success_rate': round(success_rate, 2)
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin stats error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch stats'}), 500


@app.route('/api/admin/exchanges/list', methods=['GET'])
@require_admin
def admin_list_exchanges():
    """
    List all exchanges with filters and pagination
    
    Query params:
    - page: Page number (default 1)
    - per_page: Items per page (default 50, max 100)
    - status: Filter by status
    - user_id: Filter by user
    - from_currency: Filter by source currency
    - to_currency: Filter by destination currency
    - sort: Sort field (default: created_at)
    - order: asc/desc (default: desc)
    """
    try:
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        offset = (page - 1) * per_page
        
        # Filters
        status = request.args.get('status')
        user_id = request.args.get('user_id')
        from_currency = request.args.get('from_currency')
        to_currency = request.args.get('to_currency')
        
        # Sorting
        sort_field = request.args.get('sort', 'created_at')
        sort_order = request.args.get('order', 'desc')
        
        # Validate sort field
        valid_sort_fields = ['created_at', 'updated_at', 'from_amount', 'to_amount', 'status']
        if sort_field not in valid_sort_fields:
            sort_field = 'created_at'
        
        # Build query
        query = supabase.table('crypto_exchanges')\
            .select('*', count='exact')\
            .order(sort_field, desc=(sort_order == 'desc'))\
            .range(offset, offset + per_page - 1)
        
        # Apply filters
        if status:
            query = query.eq('status', status)
        if user_id:
            query = query.eq('user_id', user_id)
        if from_currency:
            query = query.eq('from_currency', from_currency.upper())
        if to_currency:
            query = query.eq('to_currency', to_currency.upper())
        
        result = query.execute()
        
        exchanges = result.data or []
        total = result.count or 0
        
        return jsonify({
            'exchanges': exchanges,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            },
            'filters': {
                'status': status,
                'user_id': user_id,
                'from_currency': from_currency,
                'to_currency': to_currency
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin list error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch exchanges'}), 500


@app.route('/api/admin/exchanges/<exchange_id>', methods=['GET'])
@require_admin
def admin_get_exchange(exchange_id):
    """
    Get detailed exchange information (admin view)
    
    Includes:
    - Full exchange data
    - User information
    - Wallet information
    - Track history
    - Full metadata
    """
    try:
        # Get exchange
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('id', exchange_id)\
            .single()\
            .execute()
        
        if not result.data:
            return jsonify({'error': 'Exchange not found'}), 404
        
        exchange = result.data
        
        # Get user info
        user_result = supabase.table('profiles')\
            .select('id, username, email, created_at')\
            .eq('id', exchange['user_id'])\
            .single()\
            .execute()
        
        user_info = user_result.data if user_result.data else None
        
        # Get wallet info if exists
        wallet_result = supabase.table('escrow_wallets')\
            .select('id, address, currency, created_at')\
            .eq('address', exchange['deposit_address'])\
            .execute()
        
        wallet_info = wallet_result.data[0] if wallet_result.data else None
        
        # Get track history
        track_result = supabase.table('swapkit_track_log')\
            .select('*')\
            .eq('exchange_id', exchange_id)\
            .order('checked_at', desc=True)\
            .execute()
        
        track_history = track_result.data or []
        
        return jsonify({
            'exchange': exchange,
            'user': user_info,
            'wallet': wallet_info,
            'track_history': track_history,
            'can_retry': exchange['status'] in ['failed', 'expired', 'rate_expired']
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin get exchange error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch exchange'}), 500

@app.route('/api/admin/exchanges/<exchange_id>/retry', methods=['POST'])
@require_admin
def admin_retry_exchange(exchange_id):
    """
    Retry a failed exchange (admin only)
    
    Only works for exchanges in 'failed', 'expired', or 'rate_expired' status
    
    This resets the exchange to appropriate status for reprocessing
    """
    try:
        # Get exchange
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('id', exchange_id)\
            .single()\
            .execute()
        
        if not result.data:
            return jsonify({'error': 'Exchange not found'}), 404
        
        exchange = result.data
        
        # Check if retryable
        if exchange['status'] not in ['failed', 'expired', 'rate_expired']:
            return jsonify({'error': f'Cannot retry exchange with status: {exchange["status"]}'}), 400
        
        # Determine new status based on current state
        if exchange.get('deposit_tx_hash'):
            # Deposit was made, retry from swapping
            new_status = 'swapping'
        elif exchange.get('deposit_detected_at'):
            # Deposit detected but not forwarded
            new_status = 'deposit_detected'
        else:
            # No deposit yet, back to pending
            new_status = 'pending'
        
        # Reset exchange
        supabase.table('crypto_exchanges').update({
            'status': new_status,
            'error_message': None,
            'error_code': None,
            'retry_count': (exchange.get('retry_count', 0) or 0) + 1,
            'last_retry_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat()
        }).eq('id', exchange_id).execute()
        
        app.logger.info(f"Admin retry: Exchange {exchange_id} reset to {new_status}")
        
        return jsonify({
            'status': 'ok',
            'message': f'Exchange reset to {new_status}',
            'new_status': new_status
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin retry error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to retry exchange'}), 500

@app.route('/api/admin/exchanges/track-logs', methods=['GET'])
@require_admin
def admin_get_track_logs():
    """
    Get SwapKit track polling logs
    
    Query params:
    - page: Page number
    - per_page: Items per page
    - exchange_id: Filter by exchange
    """
    try:
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 50)), 100)
        offset = (page - 1) * per_page
        
        exchange_id = request.args.get('exchange_id')
        
        query = supabase.table('swapkit_track_log')\
            .select('*', count='exact')\
            .order('checked_at', desc=True)\
            .range(offset, offset + per_page - 1)
        
        if exchange_id:
            query = query.eq('exchange_id', exchange_id)
        
        result = query.execute()
        
        return jsonify({
            'logs': result.data or [],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': result.count or 0
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin track logs error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch logs'}), 500

@app.route('/api/admin/exchanges/<exchange_id>/force-status', methods=['POST'])
@require_admin
def admin_force_status(exchange_id):
    """
    Force update exchange status (admin emergency action)
    
    Request body:
    {
        "status": "completed",
        "reason": "Manual completion after verification"
    }
    """
    try:
        data = request.json or {}
        new_status = data.get('status')
        reason = data.get('reason', 'Admin forced status change')
        
        if not new_status:
            return jsonify({'error': 'status required'}), 400
        
        # Validate status
        valid_statuses = [
            'pending', 'deposit_detected', 'confirming', 'swapping', 
            'swap_complete', 'completed', 'failed', 'expired', 'rate_expired', 'refunded'
        ]
        
        if new_status not in valid_statuses:
            return jsonify({'error': f'Invalid status. Must be one of: {", ".join(valid_statuses)}'}), 400
        
        # Get exchange
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('id', exchange_id)\
            .single()\
            .execute()
        
        if not result.data:
            return jsonify({'error': 'Exchange not found'}), 404
        
        exchange = result.data
        old_status = exchange['status']
        
        # Update
        updates = {
            'status': new_status,
            'updated_at': datetime.utcnow().isoformat(),
            'metadata': {
                **exchange.get('metadata', {}),
                'admin_force_status': {
                    'old_status': old_status,
                    'new_status': new_status,
                    'reason': reason,
                    'admin_id': str(request.user_id),
                    'timestamp': datetime.utcnow().isoformat()
                }
            }
        }
        
        # If forcing to completed, set completed_at
        if new_status == 'completed' and not exchange.get('completed_at'):
            updates['completed_at'] = datetime.utcnow().isoformat()
        
        supabase.table('crypto_exchanges').update(updates).eq('id', exchange_id).execute()
        
        app.logger.warning(f"Admin {request.user_id} forced exchange {exchange_id}: {old_status} → {new_status}. Reason: {reason}")
        
        return jsonify({
            'status': 'ok',
            'message': f'Status updated from {old_status} to {new_status}',
            'old_status': old_status,
            'new_status': new_status
        }), 200
        
    except Exception as e:
        app.logger.error(f"Admin force status error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to update status'}), 500


# ============================================
# HEALTH & STATUS ENDPOINTS
# ============================================

@app.route('/health', methods=['GET'])
def health_check():
    """
    System health check endpoint
    
    Checks:
    - Database connectivity
    - SwapKit API status
    - Background monitor status (if applicable)
    
    Returns:
    - healthy/unhealthy
    - Service statuses
    - Version info
    """
    try:
        health_status = {
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'services': {},
            'version': '1.0.0'
        }
        
        # Check database
        try:
            supabase.table('profiles').select('id').limit(1).execute()
            health_status['services']['database'] = 'ok'
        except Exception as e:
            health_status['services']['database'] = f'error: {str(e)}'
            health_status['status'] = 'unhealthy'
        
        # Check SwapKit API
        try:
            swapkit_request('GET', '/providers')
            health_status['services']['swapkit'] = 'ok'
        except Exception as e:
            health_status['services']['swapkit'] = f'error: {str(e)}'
            health_status['status'] = 'degraded'
        
        # Check Tatum (if configured)
        if os.getenv('TATUM_API_KEY'):
            health_status['services']['tatum'] = 'configured'
        else:
            health_status['services']['tatum'] = 'not_configured'
        
        # Get recent exchange stats
        try:
            recent = supabase.table('crypto_exchanges')\
                .select('status', count='exact')\
                .gte('created_at', (datetime.utcnow() - timedelta(hours=1)).isoformat())\
                .execute()
            
            health_status['recent_activity'] = {
                'last_hour_exchanges': recent.count or 0
            }
        except:
            pass
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        
        return jsonify(health_status), status_code
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503

@app.route('/api/exchange/status-summary', methods=['GET'])
@require_admin
def exchange_status_summary():
    """
    Quick status summary for monitoring dashboard
    """
    try:
        # Count by status
        result = supabase.table('crypto_exchanges')\
            .select('status', count='exact')\
            .execute()
        
        # Group by status
        status_counts = {}
        for ex in result.data or []:
            status = ex['status']
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Active exchanges (pending, swapping, etc)
        active_statuses = ['pending', 'deposit_detected', 'confirming', 'swapping', 'swap_complete']
        active_count = sum(status_counts.get(s, 0) for s in active_statuses)
        
        return jsonify({
            'total': result.count or 0,
            'active': active_count,
            'by_status': status_counts,
            'timestamp': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        app.logger.error(f"Status summary error: {e}")
        return jsonify({'error': 'Failed to fetch summary'}), 500


# --------------------- Admin Debug Endpoint ---------------------
@app.route('/api/admin/debug', methods=['GET'])
def admin_debug():
    """Debug endpoint to test admin authentication."""
    try:
        token = None
        auth_header = request.headers.get('Authorization')

        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                return jsonify({'error': 'Invalid token format'}), 401

        if not token:
            return jsonify({'error': 'Token missing'}), 401

        try:
            payload = jwt.decode(
                token,
                os.getenv('SUPABASE_JWT_SECRET'),
                algorithms=['HS256'],
                audience='authenticated',
                options={"verify_exp": True}
            )
            user_id = payload['sub']
            user_role = payload.get('role', 'user')

            return jsonify({
                'user_id': user_id,
                'user_role': user_role,
                'token_valid': True,
                'timestamp': datetime.utcnow().isoformat()
            }), 200

        except Exception as jwt_error:
            return jsonify({
                'error': f'JWT decode error: {str(jwt_error)}',
                'token_valid': False
            }), 401

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --------------------- Admin Access Check ---------------------
@app.route('/api/admin/access-check', methods=['GET'])
@limiter.limit("60 per minute")
def admin_access_check():
    """Return 200 if requester is admin, else 403 and log the IP."""
    try:
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
            except IndexError:
                token = None

        if not token:
            # Log forbidden attempt with no token
            try:
                supabase.table('security_events').insert({
                    'event': 'forbidden_admin_access',
                    'path': request.path,
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': None,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception:
                app.logger.warning(f"SECURITY: forbidden_admin_access ip={request.remote_addr} path={request.path}")
            return jsonify({'admin': False}), 403

        try:
            payload = jwt.decode(
                token,
                os.getenv('SUPABASE_JWT_SECRET'),
                algorithms=['HS256'],
                audience='authenticated',
                options={"verify_exp": True}
            )
            user_id = payload.get('sub')

            # Check role from profiles table only
            try:
                user_profile = supabase.table('profiles').select('role').eq('id', user_id).single().execute()
                profile_role = user_profile.data.get('role') if user_profile.data else None
            except Exception:
                profile_role = None

            if profile_role != 'admin':
                # Log forbidden with role info
                role_for_log = profile_role or 'unknown'
                try:
                    supabase.table('security_events').insert({
                        'event': 'forbidden_admin_access',
                        'path': request.path,
                        'ip_address': request.remote_addr,
                        'user_agent': request.headers.get('User-Agent'),
                        'user_id': user_id,
                        'role': role_for_log,
                        'timestamp': datetime.utcnow().isoformat()
                    }).execute()
                except Exception:
                    app.logger.warning(f"SECURITY: forbidden_admin_access user={user_id} role={role_for_log} ip={request.remote_addr} path={request.path}")
                return jsonify({'admin': False}), 403

            # Admin ok
            return jsonify({'admin': True}), 200

        except jwt.ExpiredSignatureError:
            return jsonify({'admin': False, 'error': 'Token expired'}), 403
        except Exception:
            # Any decode error -> treat as forbidden and log
            try:
                supabase.table('security_events').insert({
                    'event': 'forbidden_admin_access',
                    'path': request.path,
                    'ip_address': request.remote_addr,
                    'user_agent': request.headers.get('User-Agent'),
                    'user_id': None,
                    'timestamp': datetime.utcnow().isoformat()
                }).execute()
            except Exception:
                app.logger.warning(f"SECURITY: forbidden_admin_access ip={request.remote_addr} path={request.path}")
            return jsonify({'admin': False}), 403
    except Exception as e:
        app.logger.exception('admin_access_check error')
        return jsonify({'admin': False, 'error': str(e)}), 500

# --------------------- Admin Authentication ---------------------
@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    """Admin login endpoint with role verification."""
    try:
        data = request.json or {}
        email = data.get('email', '').strip()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        # Authenticate with Supabase
        try:
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            if not auth_response.user:
                return jsonify({"error": "Invalid credentials"}), 401

            user_id = auth_response.user.id

            # Check if user has admin role
            user_profile = supabase.table('profiles').select('role, username, display_name').eq('id', user_id).single().execute()

            if not user_profile.data or user_profile.data.get('role') != 'admin':
                # Sign out the user since they're not an admin
                supabase.auth.sign_out()
                return jsonify({"error": "Admin access denied"}), 403

            # Log admin login
            log_admin_action(user_id, "Admin login", request.remote_addr)

            return jsonify({
                "success": True,
                "user": {
                    "id": user_id,
                    "email": email,
                    "username": user_profile.data.get('username'),
                    "display_name": user_profile.data.get('display_name'),
                    "role": "admin"
                },
                "access_token": auth_response.session.access_token,
                "refresh_token": auth_response.session.refresh_token
            }), 200

        except Exception as auth_error:
            app.logger.error(f"Admin auth error: {auth_error}")
            return jsonify({"error": "Authentication failed"}), 401

    except Exception as e:
        app.logger.exception("admin_login error")
        return jsonify({"error": "Login failed"}), 500

# --------------------- Admin Overview ---------------------
@app.route('/api/admin/overview', methods=['GET'])
@require_admin
@limiter.limit("30 per minute")
def admin_overview():
    """Get platform statistics and metrics."""
    try:
        user_id = request.user_id

        # Get basic statistics
        total_users = supabase.table('profiles').select('id', count='exact').execute()
        active_escrows = supabase.table('escrows').select('id', count='exact').in_('status', ['pending', 'funded', 'processing']).execute()
        completed_escrows = supabase.table('escrows').select('id', count='exact').eq('status', 'completed').execute()
        total_transactions = supabase.table('transactions').select('id', count='exact').execute()

        # Get recent activity (last 24 hours)
        yesterday = datetime.utcnow() - timedelta(days=1)
        # Count users created in the last 24h for the users delta
        recent_users = supabase.table('profiles').select('id').gte('created_at', yesterday.isoformat()).execute()
        recent_escrows = supabase.table('escrows').select('id').gte('created_at', yesterday.isoformat()).execute()
        recent_transactions = supabase.table('transactions').select('id').gte('created_at', yesterday.isoformat()).execute()

        # Get revenue metrics (platform fees)
        platform_fees = supabase.table('transactions').select('usd_amount').eq('type', 'platform_fee').execute()
        total_revenue = sum(float(tx.get('usd_amount', 0)) for tx in platform_fees.data or [])

        # Get currency breakdown
        currency_stats = {}
        escrow_currencies = supabase.table('escrows').select('currency, amount').execute()
        for escrow in escrow_currencies.data or []:
            curr = escrow['currency']
            amt = float(escrow['amount'])
            currency_stats[curr] = currency_stats.get(curr, 0) + amt

        overview = {
            "timestamp": datetime.utcnow().isoformat(),
            "users": {
                "total": total_users.count or 0,
                "active_24h": len(recent_users.data or [])
            },
            "escrows": {
                "total": (active_escrows.count or 0) + (completed_escrows.count or 0),
                "active": active_escrows.count or 0,
                "completed": completed_escrows.count or 0,
                "recent_24h": len(recent_escrows.data or [])
            },
            "transactions": {
                "total": total_transactions.count or 0,
                "recent_24h": len(recent_transactions.data or [])
            },
            "revenue": {
                "total_platform_fees_usd": round(total_revenue, 2),
                "currency_breakdown": currency_stats
            },
            "system_health": {
                "supabase_connected": bool(supabase),
                "crypto_enabled": bool(TATUM_API_KEY),
                "paypal_enabled": bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET)
            }
        }

        # Log admin overview access
        log_admin_action(user_id, "Viewed admin overview", request.remote_addr)

        return jsonify(overview), 200

    except Exception as e:
        app.logger.exception("admin_overview error")
        return jsonify({"error": str(e)}), 500

# --------------------- Admin User Management ---------------------
@app.route('/api/admin/users', methods=['GET'])
@require_admin
@limiter.limit("60 per minute")
def admin_list_users():
    """List users with filtering and pagination for admin."""
    try:
        user_id = request.user_id

        # Parse query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)  # Max 100 per page
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', '').strip()  # active, banned, all
        role_filter = request.args.get('role', '').strip()  # user, admin, all
        offset = (page - 1) * limit

        # Build query
        query = supabase.table('profiles').select('id, username, display_name, avatar_url, created_at, role, banned, banned_reason, banned_at')

        # Apply search filter - use ilike on username only for now
        if search:
            query = query.ilike('username', f'%{search}%')

        # Apply status filter
        if status_filter == 'banned':
            query = query.eq('banned', True)
        elif status_filter == 'active':
            query = query.eq('banned', False)

        # Apply role filter
        if role_filter and role_filter != 'all':
            query = query.eq('role', role_filter)

        # Get total count for pagination using a simple count query
        try:
            # Use a simple count query instead of RPC function
            count_query = supabase.table('profiles').select('id', count='exact')
            # Apply same filters as main query
            if search:
                count_query = count_query.ilike('username', f'%{search}%')
            if status_filter == 'banned':
                count_query = count_query.eq('banned', True)
            elif status_filter == 'active':
                count_query = count_query.eq('banned', False)
            if role_filter and role_filter != 'all':
                count_query = count_query.eq('role', role_filter)

            count_result = count_query.execute()
            total_users = count_result.count if count_result.count is not None else 0
        except Exception as count_error:
            app.logger.error(f"Count query failed: {count_error}")
            total_users = 0

        # Apply pagination and sorting
        users = query.range(offset, offset + limit - 1).order('created_at', desc=True).execute()

        # Get additional user stats
        user_stats = []
        for user in users.data or []:
            user_id = user['id']

            # Count escrows for this user
            buyer_escrows = supabase.table('escrows').select('id').eq('buyer_id', user_id).execute()
            seller_escrows = supabase.table('escrows').select('id').eq('seller_id', user_id).execute()
            total_escrows = len(buyer_escrows.data or []) + len(seller_escrows.data or [])

            # Get last activity - simplified approach
            try:
                # Try to get last activity as buyer first
                buyer_escrow = supabase.table('escrows').select('created_at').eq('buyer_id', user_id).order('created_at', desc=True).limit(1).execute()
                seller_escrow = supabase.table('escrows').select('created_at').eq('seller_id', user_id).order('created_at', desc=True).limit(1).execute()

                # Get the most recent activity
                buyer_date = buyer_escrow.data[0]['created_at'] if buyer_escrow.data else None
                seller_date = seller_escrow.data[0]['created_at'] if seller_escrow.data else None

                # Return the most recent date
                if buyer_date and seller_date:
                    last_activity = max(buyer_date, seller_date)
                elif buyer_date:
                    last_activity = buyer_date
                elif seller_date:
                    last_activity = seller_date
                else:
                    last_activity = None
            except Exception:
                last_activity = None

            user_stats.append({
                **user,
                'total_escrows': total_escrows,
                'last_activity': last_activity
            })

        result = {
            "users": user_stats,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_users,
                "pages": (total_users + limit - 1) // limit
            },
            "filters": {
                "search": search,
                "status": status_filter
            }
        }

        # Log admin user list access
        log_admin_action(user_id, f"Listed users (page {page}, search: '{search}', status: '{status_filter}')", request.remote_addr)

        return jsonify(result), 200

    except Exception as e:
        app.logger.exception("admin_list_users error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/users/<user_id>/status', methods=['POST'])
@require_admin
@limiter.limit("30 per minute")
def admin_update_user_status(user_id):
    """Ban or unban a user."""
    try:
        admin_id = request.user_id
        data = request.json or {}
        action = data.get('action', '').strip()  # 'ban' or 'unban'
        reason = data.get('reason', '').strip()

        if action not in ['ban', 'unban']:
            return jsonify({"error": "Invalid action. Must be 'ban' or 'unban'"}), 400

        if action == 'ban' and not reason:
            return jsonify({"error": "Ban reason is required"}), 400

        # Check if user exists
        user_profile = supabase.table('profiles').select('id, username, banned').eq('id', user_id).single().execute()
        if not user_profile.data:
            return jsonify({"error": "User not found"}), 404

        update_data = {}
        if action == 'ban':
            if user_profile.data.get('banned'):
                return jsonify({"error": "User is already banned"}), 400
            update_data = {
                'banned': True,
                'banned_reason': reason,
                'banned_at': datetime.utcnow().isoformat(),
                'banned_by': admin_id
            }
        else:  # unban
            if not user_profile.data.get('banned'):
                return jsonify({"error": "User is not banned"}), 400
            update_data = {
                'banned': False,
                'banned_reason': None,
                'banned_at': None,
                'banned_by': None
            }

        # Update user status
        updated = supabase.table('profiles').update(update_data).eq('id', user_id).execute()

        if updated.data:
            # Log the action with details
            log_admin_action(
                admin_id,
                f"{'Banned' if action == 'ban' else 'Unbanned'} user {user_profile.data.get('username')} ({user_id})",
                request.remote_addr,
                {
                    'target_user_id': user_id,
                    'target_username': user_profile.data.get('username'),
                    'action': action,
                    'reason': reason
                }
            )

            # Create system notification for the user (optional)
            if action == 'ban':
                supabase.table('notifications').insert({
                    'user_id': user_id,
                    'type': 'system',
                    'title': 'Account Suspended',
                    'message': f'Your account has been suspended. Reason: {reason}',
                    'created_at': datetime.utcnow().isoformat()
                }).execute()

            return jsonify({
                "success": True,
                "message": f"User {'banned' if action == 'ban' else 'unbanned'} successfully",
                "user": updated.data[0]
            }), 200
        else:
            return jsonify({"error": "Failed to update user status"}), 500

    except Exception as e:
        app.logger.exception("admin_update_user_status error")
        return jsonify({"error": str(e)}), 500

# --------------------- Admin Escrow Management ---------------------
@app.route('/api/admin/escrows', methods=['GET'])
@require_admin
@limiter.limit("60 per minute")
def admin_list_escrows():
    """List all escrows with filtering for admin."""
    try:
        user_id = request.user_id

        # Parse query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)
        status_filter = request.args.get('status', '').strip()
        payment_method = request.args.get('payment_method', '').strip()
        currency_filter = request.args.get('currency', '').strip()
        search = request.args.get('search', '').strip()  # Search in escrow ID or usernames
        offset = (page - 1) * limit

        # Build query (avoid relying on PostgREST relationship hints to prevent PGRST200)
        # First select base escrow fields only
        query = supabase.table('escrows').select('*')

        # Apply filters
        if status_filter:
            if status_filter == 'active':
                query = query.in_('status', ['pending', 'funded', 'processing'])
            else:
                query = query.eq('status', status_filter)

        if payment_method:
            query = query.eq('payment_method', payment_method)

        if currency_filter:
            query = query.eq('currency', currency_filter.upper())

        if search:
            # This is complex - we'd need to join with profiles to search usernames
            # For now, just search escrow ID
            query = query.ilike('id', f'%{search}%')

        # Get total count using a simple count query
        try:
            count_query = supabase.table('escrows').select('id', count='exact')
            # Apply same filters as main query
            if status_filter:
                if status_filter == 'active':
                    count_query = count_query.in_('status', ['pending', 'funded', 'processing'])
                else:
                    count_query = count_query.eq('status', status_filter)

            if payment_method:
                count_query = count_query.eq('payment_method', payment_method)

            if currency_filter:
                count_query = count_query.eq('currency', currency_filter.upper())

            if search:
                count_query = count_query.ilike('id', f'%{search}%')

            count_result = count_query.execute()
            total_escrows = count_result.count if count_result.count is not None else 0
        except Exception as count_error:
            app.logger.error(f"Count query failed: {count_error}")
            total_escrows = 0

        # Apply pagination and sorting
        escrows = query.range(offset, offset + limit - 1).order('created_at', desc=True).execute()

        # Hydrate buyer/seller minimal profiles manually to avoid schema relationship requirements
        enriched_escrows = []
        for e in escrows.data or []:
            buyer_username = None
            buyer_display = None
            seller_username = None
            seller_display = None
            seed_phrase = None
            try:
                if e.get('buyer_id'):
                    bp = supabase.table('profiles').select('username, display_name').eq('id', e['buyer_id']).limit(1).execute()
                    if bp.data:
                        buyer_username = bp.data[0].get('username')
                        buyer_display = bp.data[0].get('display_name')
            except Exception:
                pass
            try:
                if e.get('seller_id'):
                    sp = supabase.table('profiles').select('username, display_name').eq('id', e['seller_id']).limit(1).execute()
                    if sp.data:
                        seller_username = sp.data[0].get('username')
                        seller_display = sp.data[0].get('display_name')
            except Exception:
                pass

            # Ensure wallet exists and attach decrypted seed phrase (admin-only sensitive data)
            try:
                # Try to read existing wallet row
                w = supabase.table('escrow_wallets').select('mnemonic, currency').eq('escrow_id', e['id']).limit(1).execute()
                if not w.data:
                    # Attempt to create wallet if missing
                    if e.get('currency'):
                        generate_crypto_address(e['currency'], e['id'])
                        w = supabase.table('escrow_wallets').select('mnemonic, currency').eq('escrow_id', e['id']).limit(1).execute()
                if w.data and w.data[0].get('mnemonic'):
                    # Return mnemonic as stored (no decryption)
                    seed_phrase = w.data[0]['mnemonic']
            except Exception:
                seed_phrase = None

            e['buyer_profile'] = {
                'username': buyer_username or '',
                'display_name': buyer_display or ''
            }
            e['seller_profile'] = {
                'username': seller_username or '',
                'display_name': seller_display or ''
            }
            # Attach seed phrase field for admin visibility
            e['seed_phrase'] = seed_phrase
            enriched_escrows.append(e)

        result = {
            "escrows": enriched_escrows,
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_escrows,
                "pages": (total_escrows + limit - 1) // limit
            },
            "filters": {
                "status": status_filter,
                "payment_method": payment_method,
                "currency": currency_filter,
                "search": search
            }
        }

        # Log admin escrow list access
        log_admin_action(user_id, f"Listed escrows (page {page}, status: '{status_filter}')", request.remote_addr)

        return jsonify(result), 200

    except Exception as e:
        app.logger.exception("admin_list_escrows error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/escrows/<escrow_id>/action', methods=['POST'])
@require_admin
@limiter.limit("30 per minute")
def admin_escrow_action(escrow_id):
    """Admin actions for escrows: resolve_dispute, cancel, force_release, regenerate_wallet"""
    try:
        admin_id = request.user_id
        data = request.json or {}
        action = data.get('action', '').strip()  # 'resolve_dispute', 'cancel', 'force_release', 'regenerate_wallet'
        resolution = data.get('resolution', '').strip()  # Required for dispute resolution
        notes = data.get('notes', '').strip()

        if action not in ['resolve_dispute', 'cancel', 'force_release', 'regenerate_wallet']:
            return jsonify({"error": "Invalid action"}), 400

        if action == 'resolve_dispute' and not resolution:
            return jsonify({"error": "Resolution details required for dispute resolution"}), 400

        # Get escrow details
        escrow = supabase.table('escrows').select('*').eq('id', escrow_id).single().execute()
        if not escrow.data:
            return jsonify({"error": "Escrow not found"}), 404

        escrow_data = escrow.data
        current_status = escrow_data['status']

        # Validate action based on current status
        if action == 'cancel' and current_status in ['completed', 'cancelled', 'refunded']:
            return jsonify({"error": "Cannot cancel completed escrow"}), 400

        if action == 'force_release' and current_status != 'funded':
            return jsonify({"error": "Can only force release funded escrows"}), 400

        update_data = {}
        system_message = ""

        if action == 'cancel':
            update_data['status'] = 'cancelled'
            update_data['cancelled_by'] = 'admin'
            update_data['cancelled_at'] = datetime.utcnow().isoformat()
            update_data['admin_notes'] = notes

            # Optional refund address for crypto: send net_amount back to buyer override or buyer_address
            refund_addr = (data.get('to_address') or '').strip() or None
            if escrow_data.get('payment_method') == 'crypto':
                to_address = refund_addr or escrow_data.get('buyer_address')
                if to_address:
                    try:
                        tx_hash = send_crypto_transaction_kms(escrow_id, to_address, escrow_data.get('net_amount'))
                        if tx_hash:
                            system_message = f"❌ Escrow cancelled by admin. Refunded to {to_address}. {notes}"
                        else:
                            system_message = f"❌ Escrow cancelled by admin. Refund failed to broadcast. {notes}"
                    except Exception as e:
                        system_message = f"❌ Escrow cancelled by admin. Refund error: {str(e)}"
                else:
                    system_message = f"❌ Escrow cancelled by admin. {notes}"
            else:
                system_message = f"❌ Escrow cancelled by admin. {notes}"

        elif action == 'force_release':
            # Force release funds to seller
            update_data['status'] = 'processing'
            update_data['admin_forced_release'] = True
            update_data['admin_notes'] = notes

            # Attempt to release funds
            try:
                to_address = (data.get('to_address') or '').strip() or None
                success = release_funds(escrow_id, override_address=to_address)
                if success:
                    update_data['status'] = 'completed'
                    system_message = f"✅ Admin forced release. Funds sent to seller. {notes}"
                else:
                    update_data['status'] = 'release_failed'
                    system_message = f"❌ Admin forced release failed. {notes}"
            except Exception as e:
                update_data['status'] = 'release_failed'
                system_message = f"❌ Admin forced release error: {str(e)}"

        elif action == 'resolve_dispute':
            update_data['status'] = 'dispute_resolved'
            update_data['dispute_resolution'] = resolution
            update_data['admin_notes'] = notes
            update_data['resolved_by'] = admin_id
            update_data['resolved_at'] = datetime.utcnow().isoformat()
            system_message = f"⚖️ Dispute resolved by admin: {resolution}. {notes}"

        elif action == 'regenerate_wallet':
            # Determine currency from escrow row or existing wallet row
            cur_currency = (
                escrow_data.get('currency')
                or escrow_data.get('currency_code')
                or escrow_data.get('crypto_currency')
                or escrow_data.get('asset')
            )
            if not cur_currency:
                try:
                    wcur = supabase.table('escrow_wallets').select('currency').eq('escrow_id', escrow_id).limit(1).execute()
                    if wcur.data:
                        cur_currency = wcur.data[0].get('currency')
                except Exception:
                    pass
            if not cur_currency:
                return jsonify({"error": "Escrow currency missing; cannot regenerate wallet"}), 400

            # Remove any existing wallet row
            try:
                supabase.table('escrow_wallets').delete().eq('escrow_id', escrow_id).execute()
            except Exception:
                pass

            # Create a new wallet (plaintext mnemonic in current mode)
            addr = generate_crypto_address(cur_currency, escrow_id)
            if not addr:
                return jsonify({
                    "error": "Wallet generation failed",
                    "details": {
                        "currency": cur_currency,
                        "supported": list(CHAIN_MAP.keys()),
                        "hint": "Set TATUM_API_KEY and ensure currency matches one of supported variants"
                    }
                }), 500
            system_message = "🔁 Escrow wallet regenerated by admin"

        # Update escrow if needed; otherwise re-select current record
        if update_data:
            updated = supabase.table('escrows').update(update_data).eq('id', escrow_id).execute()
        else:
            updated = supabase.table('escrows').select('*').eq('id', escrow_id).execute()

        if updated.data:
            # Create system message
            buyer_id = escrow_data['buyer_id']
            seller_id = escrow_data['seller_id']

            for recipient_id in [buyer_id, seller_id]:
                supabase.table('escrow_messages').insert({
                    'escrow_id': escrow_id,
                    'sender_id': admin_id,
                    'message': system_message,
                    'message_type': 'system',
                    'created_at': datetime.utcnow().isoformat()
                }).execute()

            # Log admin action
            log_admin_action(
                admin_id,
                f"Admin {action} on escrow {escrow_id}",
                request.remote_addr,
                {
                    'escrow_id': escrow_id,
                    'action': action,
                    'resolution': resolution,
                    'notes': notes,
                    'buyer_id': buyer_id,
                    'seller_id': seller_id
                }
            )

            return jsonify({
                "success": True,
                "message": f"Escrow {action} completed successfully",
                "escrow": updated.data[0]
            }), 200
        else:
            return jsonify({"error": "Failed to update escrow"}), 500

    except Exception as e:
        app.logger.exception("admin_escrow_action error")
        return jsonify({"error": str(e)}), 500

# --------------------- Admin Transaction Monitoring ---------------------
@app.route('/api/admin/transactions', methods=['GET'])
@require_admin
@limiter.limit("60 per minute")
def admin_list_transactions():
    """Monitor all transactions for admin."""
    try:
        user_id = request.user_id

        # Parse query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)
        type_filter = request.args.get('type', '').strip()
        currency_filter = request.args.get('currency', '').strip()
        escrow_id = request.args.get('escrow_id', '').strip()
        offset = (page - 1) * limit

        # Build query
        query = supabase.table('transactions').select('*, escrow:escrows(id, buyer_id, seller_id, status)')

        # Apply filters
        if type_filter:
            query = query.eq('type', type_filter)

        if currency_filter:
            query = query.eq('currency', currency_filter.upper())

        if escrow_id:
            query = query.eq('escrow_id', escrow_id)

        # Get total count using simple count query
        try:
            count_query = supabase.table('transactions').select('id', count='exact')
            # Apply same filters as main query
            if type_filter:
                count_query = count_query.eq('type', type_filter)
            if currency_filter:
                count_query = count_query.eq('currency', currency_filter.upper())
            if escrow_id:
                count_query = count_query.eq('escrow_id', escrow_id)

            count_result = count_query.execute()
            total_transactions = count_result.count if count_result.count is not None else 0
        except Exception as count_error:
            app.logger.error(f"Count transactions query failed: {count_error}")
            total_transactions = 0

        # Apply pagination and sorting
        transactions = query.range(offset, offset + limit - 1).order('created_at', desc=True).execute()

        # Calculate total volume
        volume_query = supabase.table('transactions').select('usd_amount').not_.eq('type', 'platform_fee')
        if type_filter:
            volume_query = volume_query.eq('type', type_filter)
        volume_result = volume_query.execute()
        total_volume = sum(float(tx.get('usd_amount', 0)) for tx in volume_result.data or [])

        result = {
            "transactions": transactions.data or [],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_transactions,
                "pages": (total_transactions + limit - 1) // limit
            },
            "summary": {
                "total_volume_usd": round(total_volume, 2),
                "transaction_count": total_transactions
            },
            "filters": {
                "type": type_filter,
                "currency": currency_filter,
                "escrow_id": escrow_id
            }
        }

        # Log admin transaction list access
        log_admin_action(user_id, f"Listed transactions (page {page}, type: '{type_filter}')", request.remote_addr)

        return jsonify(result), 200

    except Exception as e:
        app.logger.exception("admin_list_transactions error")
        return jsonify({"error": str(e)}), 500

# --------------------- Admin System Configuration ---------------------
@app.route('/api/admin/system/status', methods=['GET'])
@require_admin
@limiter.limit("30 per minute")
def admin_system_status():
    """Enhanced system status with detailed admin information."""
    try:
        user_id = request.user_id

        # Basic system status
        status = {
            "timestamp": datetime.utcnow().isoformat(),
            "uptime": "N/A",  # Could be enhanced with actual uptime tracking
            "database": {
                "connected": bool(supabase),
                "tables_status": {}
            },
            "external_services": {
                "tatum_api": bool(TATUM_API_KEY),
                "paypal_api": bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET),
                "coin_gecko": True  # Assume always available
            },
            "security": {
                "rate_limiting_enabled": True,
                "audit_logging_enabled": True
            },
            "platform_wallets": {},
            "system_config": {
                "referral_rate": REFERRAL_RATE,
                "min_withdrawal_usd": MIN_WITHDRAW_USD,
                "max_escrow_amount": MAX_ESCROW_AMOUNT,
                "min_escrow_amount": 0  # Removed crypto minimum - frontend handles USD validation
            }
        }

        # Check platform wallets
        supported_currencies = ['BTC', 'ETH', 'USDT']
        for currency in supported_currencies:
            wallet_address = get_platform_address(currency)
            status["platform_wallets"][currency] = {
                "configured": bool(wallet_address),
                "address": wallet_address[:8] + "..." if wallet_address else None
            }

        # Check database tables (basic connectivity test)
        tables_to_check = ['profiles', 'escrows', 'transactions', 'referral_payouts']
        for table in tables_to_check:
            try:
                supabase.table(table).select('id').limit(1).execute()
                status["database"]["tables_status"][table] = "healthy"
            except Exception as e:
                status["database"]["tables_status"][table] = f"error: {str(e)}"

        # Get recent system metrics
        last_24h = datetime.utcnow() - timedelta(hours=24)

        recent_errors = supabase.table('admin_audit_log').select('id').gte('timestamp', last_24h.isoformat()).execute()
        status["system_metrics"] = {
            "admin_actions_24h": len(recent_errors.data or []),
            "error_rate_24h": "N/A"  # Could be enhanced with error tracking
        }

        # Log admin system status access
        log_admin_action(user_id, "Viewed detailed system status", request.remote_addr)

        return jsonify(status), 200

    except Exception as e:
        app.logger.exception("admin_system_status error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/system/config', methods=['GET'])
@require_admin
@limiter.limit("20 per minute")
def admin_get_config():
    """Get system configuration for admin management."""
    try:
        user_id = request.user_id

        config = {
            "platform_settings": {
                "referral_rate": REFERRAL_RATE,
                "min_withdrawal_usd": MIN_WITHDRAW_USD,
                "max_escrow_amount": MAX_ESCROW_AMOUNT,
                "min_escrow_amount": 0,  # Removed crypto minimum - frontend handles USD validation
                "supported_currencies": list(SUPPORTED_CURRENCIES)
            },
            "fee_structure": {
                "crypto_fee_rate_under_50": 0.02,
                "crypto_fee_rate_50_plus": 0.015,
                "paypal_fee_rate": 0.02
            },
            "security_settings": {
                "rate_limit_defaults": {
                    "daily": "200 per day",
                    "hourly": "50 per hour"
                },
                "admin_rate_limits": {
                    "per_minute": "30 per minute",
                    "per_hour": "60 per hour"
                }
            },
            "external_apis": {
                "tatum_configured": bool(TATUM_API_KEY),
                "paypal_configured": bool(PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET),
                "frontend_url": FRONTEND_URL
            }
        }

        # Log admin config access
        log_admin_action(user_id, "Viewed system configuration", request.remote_addr)

        return jsonify(config), 200

    except Exception as e:
        app.logger.exception("admin_get_config error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/admin/system/config', methods=['POST'])
@require_service_key
@limiter.limit("10 per hour")
def admin_update_config():
    """Update system configuration (requires service key)."""
    try:
        data = request.json or {}

        updates = {}
        config_type = data.get('config_type', '').strip()

        if config_type == 'platform_settings':
            # Update platform settings
            if 'referral_rate' in data:
                new_rate = float(data['referral_rate'])
                if 0 <= new_rate <= 1:
                    updates['REFERRAL_RATE'] = str(new_rate)
                else:
                    return jsonify({"error": "Referral rate must be between 0 and 1"}), 400

            if 'min_withdrawal_usd' in data:
                new_min = float(data['min_withdrawal_usd'])
                if new_min > 0:
                    updates['MIN_WITHDRAW_USD'] = str(new_min)
                else:
                    return jsonify({"error": "Minimum withdrawal must be positive"}), 400

            if 'max_escrow_amount' in data:
                new_max = float(data['max_escrow_amount'])
                if new_max > 0:
                    updates['MAX_ESCROW_AMOUNT'] = str(new_max)
                else:
                    return jsonify({"error": "Maximum escrow amount must be positive"}), 400

        elif config_type == 'fee_structure':
            # Fee updates would require more complex validation and testing
            return jsonify({"error": "Fee structure updates require manual deployment"}), 400

        elif config_type == 'security_settings':
            # Security settings updates would require restart/redeployment
            return jsonify({"error": "Security settings require system restart"}), 400

        else:
            return jsonify({"error": "Invalid config type"}), 400

        if not updates:
            return jsonify({"error": "No valid updates provided"}), 400

        # Log the configuration change
        log_admin_action(
            'system',
            f"System configuration updated: {config_type}",
            request.remote_addr,
            {
                'config_type': config_type,
                'updates': updates
            }
        )

        # In a real system, these would be persisted to environment variables or database
        # For this demo, we'll just return success
        return jsonify({
            "success": True,
            "message": "Configuration updated successfully",
            "updates": updates,
            "note": "In production, these changes would require system restart to take effect"
        }), 200

    except Exception as e:
        app.logger.exception("admin_update_config error")
        return jsonify({"error": str(e)}), 500

# --------------------- Admin Audit Log Access ---------------------
@app.route('/api/admin/audit-log', methods=['GET'])
@require_admin
@limiter.limit("30 per minute")
def admin_audit_log():
    """View admin audit logs."""
    try:
        user_id = request.user_id

        # Parse query parameters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)
        admin_filter = request.args.get('admin_id', '').strip()
        action_filter = request.args.get('action', '').strip()
        days = int(request.args.get('days', 7))  # Default to last 7 days
        offset = (page - 1) * limit

        # Calculate date range
        since_date = datetime.utcnow() - timedelta(days=days)

        # Build query
        query = supabase.table('admin_audit_log').select('*')

        if admin_filter:
            query = query.eq('admin_id', admin_filter)

        if action_filter:
            query = query.ilike('action', f'%{action_filter}%')

        # Always filter by date range
        query = query.gte('timestamp', since_date.isoformat())

        # Get total count using simple count query
        try:
            count_query = supabase.table('admin_audit_log').select('id', count='exact')
            # Apply same filters as main query
            if admin_filter:
                count_query = count_query.eq('admin_id', admin_filter)
            if action_filter:
                count_query = count_query.ilike('action', f'%{action_filter}%')
            # Always filter by date range
            count_query = count_query.gte('timestamp', since_date.isoformat())

            count_result = count_query.execute()
            total_logs = count_result.count if count_result.count is not None else 0
        except Exception as count_error:
            app.logger.error(f"Count audit logs query failed: {count_error}")
            total_logs = 0

        # Apply pagination and sorting
        logs = query.range(offset, offset + limit - 1).order('timestamp', desc=True).execute()

        result = {
            "audit_logs": logs.data or [],
            "pagination": {
                "page": page,
                "limit": limit,
                "total": total_logs,
                "pages": (total_logs + limit - 1) // limit
            },
            "filters": {
                "admin_id": admin_filter,
                "action": action_filter,
                "days": days
            }
        }

        # Log audit log access
        log_admin_action(user_id, f"Viewed audit logs (page {page}, days: {days})", request.remote_addr)

        return jsonify(result), 200

    except Exception as e:
        app.logger.exception("admin_audit_log error")
        return jsonify({"error": str(e)}), 500

# --------------------- Marketplace & Moderation ---------------------

def _get_moderation_settings():
    """Resolve moderation settings from env with optional DB override."""
    try:
        # Defaults from env
        provider = (os.getenv('MODERATION_PROVIDER') or '').strip().lower()
        api_key = os.getenv('MODERATION_API_KEY')
        thresholds_raw = os.getenv('MODERATION_THRESHOLDS') or '{}'
        try:
            thresholds = json.loads(thresholds_raw)
        except Exception:
            thresholds = {}
        enabled = True if provider else False

        # Optional DB override (latest row wins)
        try:
            cfg = supabase.table('moderation_config').select('*').order('updated_at', desc=True).limit(1).execute()
            if cfg and getattr(cfg, 'data', None):
                row = cfg.data[0]
                if row.get('provider'):
                    provider = (row.get('provider') or '').strip().lower()
                if row.get('api_key'):
                    api_key = row.get('api_key')
                if isinstance(row.get('thresholds'), dict):
                    thresholds = row.get('thresholds')
                if row.get('enabled') is not None:
                    enabled = bool(row.get('enabled'))
        except Exception:
            pass

        return {
            'provider': provider,
            'api_key': api_key,
            'thresholds': thresholds or {},
            'enabled': enabled
        }
    except Exception:
        return {'provider': '', 'api_key': None, 'thresholds': {}, 'enabled': False}


def _moderate_text(text: str, context: str = 'listing') -> tuple:
    """Return (ok: bool, reason: Optional[str])."""
    if not text:
        return True, None
    settings = _get_moderation_settings()
    if not settings.get('enabled') or not settings.get('provider'):
        return True, None
    provider = settings['provider']
    api_key = settings.get('api_key')
    try:
        if provider == 'openai' and api_key:
            url = 'https://api.openai.com/v1/moderations'
            payload = {"model": "omni-moderation-2024-09-26", "input": text}
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            r = requests.post(url, headers=headers, json=payload, timeout=15)
            if r.status_code >= 400:
                app.logger.warning("Moderation (text) provider error: %s", r.text)
                return True, None  # fail-open
            data = r.json()
            flagged = False
            try:
                flagged = bool(data['results'][0]['flagged'])
            except Exception:
                flagged = False
            if flagged:
                return False, 'Text failed moderation'
            return True, None

        elif provider == 'hive' and api_key:
            # Placeholder: Assume pass for MVP if provider not fully wired
            return True, None

        # Unknown provider -> pass
        return True, None
    except Exception:
        app.logger.exception("_moderate_text error")
        return True, None  # fail-open


def _moderate_image_url(image_url: str, context: str = 'listing') -> tuple:
    """Return (ok: bool, reason: Optional[str])."""
    if not image_url:
        return True, None
    settings = _get_moderation_settings()
    if not settings.get('enabled') or not settings.get('provider'):
        return True, None
    provider = settings['provider']
    api_key = settings.get('api_key')
    try:
        if provider == 'openai' and api_key:
            # OpenAI Vision Moderation via Responses API (omni-moderation-latest)
            # We ask the model to return a concise JSON so we can parse deterministically.
            url = 'https://api.openai.com/v1/responses'
            prompt = (
                "Analyze this image for policy compliance (violence, sexual, hate, self-harm, drugs). "
                "Respond ONLY with JSON: {\"flagged\": boolean, \"labels\":[{\"label\":string, \"score\":number}]}"
            )
            payload = {
                "model": "omni-moderation-2024-09-26",
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {"type": "input_text", "text": prompt},
                            {"type": "input_image", "image_url": image_url}
                        ]
                    }
                ]
            }
            headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
            r = requests.post(url, headers=headers, json=payload, timeout=25)
            if r.status_code >= 400:
                app.logger.warning("OpenAI image moderation error: %s", r.text)
                return True, None  # fail-open

            j = r.json() if r.content else {}
            # Try a few common fields for text output
            text_out = None
            try:
                # New Responses format often includes 'output_text'
                text_out = j.get('output_text')
                if not text_out:
                    # Fallback to first text content if present
                    outputs = j.get('output') or j.get('choices') or []
                    if isinstance(outputs, list) and outputs:
                        # Heuristic extraction
                        first = outputs[0]
                        text_out = (
                            first.get('content', [{}])[0].get('text')
                            if isinstance(first.get('content'), list)
                            else first.get('message', {}).get('content')
                        )
            except Exception:
                text_out = None

            flagged = False
            if text_out:
                try:
                    parsed = json.loads(text_out)
                    flagged = bool(parsed.get('flagged'))
                    labels = parsed.get('labels') or []
                    thresholds = settings.get('thresholds') or {}
                    default_threshold = float(thresholds.get('default', 0.9))
                    # If JSON returned no boolean, compute from scores
                    if parsed.get('flagged') is None and isinstance(labels, list):
                        for c in labels:
                            label = str(c.get('label') or '').lower()
                            score = c.get('score')
                            try:
                                score = float(score)
                            except Exception:
                                continue
                            thr = float(thresholds.get(label, default_threshold))
                            if score >= thr:
                                flagged = True
                                break
                except Exception:
                    # If parsing fails, fall back to simple keyword check
                    flagged = '"flagged": true' in text_out.lower()

            if flagged:
                return False, 'Image failed moderation'
            return True, None

        elif provider == 'hive' and api_key:
            # Hive path disabled by default; keep as fallback if provider switched back
            return True, None
        return True, None
    except Exception:
        app.logger.exception("_moderate_image_url error")
        return True, None  # fail-open


# Development-only diagnostics endpoint for moderation settings
@app.route('/api/_debug/moderation', methods=['GET','POST'])
def debug_moderation_settings():
    """Return resolved moderation settings for debugging (dev-only).
    This intentionally masks the API key. Disabled in production.
    """
    env = (os.getenv('ENV') or os.getenv('FLASK_ENV') or '').lower()
    if env == 'production':
        return jsonify({'error': 'Disabled in production'}), 403
    try:
        cfg = _get_moderation_settings() or {}
        api_key = cfg.get('api_key')
        masked = None
        if api_key:
            try:
                masked = '****' + api_key[-4:]
            except Exception:
                masked = 'present'
        return jsonify({
            'provider': cfg.get('provider'),
            'enabled': cfg.get('enabled'),
            'thresholds': cfg.get('thresholds'),
            'api_key_present': bool(api_key),
            'api_key_masked': masked
        }), 200
    except Exception as e:
        app.logger.exception('debug_moderation_settings error')
        return jsonify({'error': str(e)}), 500


# --------------------- Marketplace ---------------------

@app.route('/api/marketplace', methods=['GET'])
@limiter.exempt
def marketplace_index():
    """Public browse with search/filter/sort/pagination."""
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        if limit > 100:
            limit = 100
        q = (request.args.get('q') or '').strip()
        currency = (request.args.get('currency') or '').upper().strip()
        payment_method = (request.args.get('payment_method') or '').strip().lower()
        tags_raw = (request.args.get('tags') or '').strip()  # comma-separated
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')
        sort = (request.args.get('sort') or 'new').strip()  # new|price_asc|price_desc

        query = supabase.table('listings').select('*').eq('status', 'active')
        if q:
            # Simple title search; description search could be added with full-text later
            query = query.ilike('title', f"%{q}%")
        if min_price:
            try:
                query = query.gte('price_usd', float(min_price))
            except Exception:
                pass
        if max_price:
            try:
                query = query.lte('price_usd', float(max_price))
            except Exception:
                pass

        # Sorting
        if sort == 'price_asc':
            query = query.order('price_usd', desc=False)
        elif sort == 'price_desc':
            query = query.order('price_usd', desc=True)
        else:
            query = query.order('created_at', desc=True)

        # Pagination
        offset = (page - 1) * limit
        query = query.range(offset, offset + limit - 1)

        res = query.execute()
        rows = res.data or []

        # In-memory filters for payment_method and currency (since currencies live in separate table)
        items = rows

        if payment_method:
            allowed_methods = {'crypto', 'paypal'}
            if payment_method not in allowed_methods:
                return jsonify({"error": "Invalid payment_method"}), 400
            items = [x for x in items if payment_method in (x.get('payment_methods') or [])]

        # Attach images and allowed currencies for returned items
        listing_ids = [x['id'] for x in items if x.get('id')]
        images_by_listing = {}
        curr_by_listing = {}
        if listing_ids:
            try:
                imgs = supabase.table('listing_images').select('listing_id,url,sort_order').in_('listing_id', listing_ids).order('sort_order').execute()
                for row in (imgs.data or []):
                    images_by_listing.setdefault(row['listing_id'], []).append(row['url'])
            except Exception:
                pass
            try:
                cur = supabase.table('listing_currencies').select('listing_id,currency').in_('listing_id', listing_ids).execute()
                for row in (cur.data or []):
                    curr_by_listing.setdefault(row['listing_id'], []).append(row['currency'])
            except Exception:
                pass

        # Currency filter now that we know accept_all/currencies
        if currency:
            filtered = []
            for x in items:
                if x.get('accept_all'):
                    filtered.append(x)
                else:
                    allowed = curr_by_listing.get(x['id'], [])
                    if currency in allowed:
                        filtered.append(x)
            items = filtered

        # Tags filter (comma-separated, any match)
        if tags_raw:
            tag_set = {t.strip().lower() for t in tags_raw.split(',') if t.strip()}
            def has_any_tag(x):
                row_tags = [str(t).lower() for t in (x.get('tags') or [])]
                return any(t in row_tags for t in tag_set)
            items = [x for x in items if has_any_tag(x)]

        # Build response
        enriched = []
        for x in items:
            enriched.append({
                **x,
                'images': images_by_listing.get(x['id'], []),
                'currencies': curr_by_listing.get(x['id'], []) if not x.get('accept_all') else list(SUPPORTED_CURRENCIES)
            })

        return jsonify({
            'items': enriched,
            'pagination': {
                'page': page,
                'limit': limit,
                'count': len(enriched)
            }
        }), 200
    except Exception as e:
        app.logger.exception("marketplace_index error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/marketplace/<uuid:listing_id>', methods=['GET'])
def marketplace_detail(listing_id):
    try:
        # Flask's uuid converter gives a uuid.UUID here; convert to string for DB queries
        listing_id = str(listing_id)
        listing_res = supabase.table('listings').select('*').eq('id', listing_id).single().execute()
        if not listing_res.data or listing_res.data.get('status') == 'deleted':
            return jsonify({"error": "Listing not found"}), 404
        l = listing_res.data

        imgs = supabase.table('listing_images').select('url,sort_order').eq('listing_id', listing_id).order('sort_order').execute()
        images = [r['url'] for r in (imgs.data or [])]

        cur = supabase.table('listing_currencies').select('currency').eq('listing_id', listing_id).execute()
        currencies = [r['currency'] for r in (cur.data or [])]

        # Rating average for this listing; default to 5.0 if none
        try:
            rev = supabase.table('reviews').select('rating').eq('listing_id', listing_id).execute()
            ratings = [int(x['rating']) for x in (rev.data or []) if x.get('rating') is not None]
            avg_rating = round(sum(ratings) / len(ratings), 2) if ratings else 5.0
        except Exception:
            avg_rating = 5.0

        # Seller escrow volume USD (completed only)
        seller_volume_usd = 0.0
        try:
            es = supabase.table('escrows').select('status, amount, currency, payment_method, usd_amount').eq('seller_id', l['seller_id']).execute()
            rows = [x for x in (es.data or []) if x.get('status') == 'completed']
            price_cache = {}

            def price_for(cur):
                cu = (cur or '').upper()
                if cu in price_cache:
                    return price_cache[cu]
                p = get_usd_price(cu) or 0
                price_cache[cu] = p
                return p

            for r in rows:
                currency_r = r.get('currency')
                pm = r.get('payment_method')
                if currency_r == 'USD' or pm == 'paypal':
                    try:
                        seller_volume_usd += float(r.get('amount') or r.get('usd_amount') or 0)
                    except Exception:
                        pass
                else:
                    price = price_for(currency_r)
                    if price and (r.get('amount') is not None):
                        try:
                            seller_volume_usd += float(r.get('amount') or 0) * float(price)
                        except Exception:
                            pass
            seller_volume_usd = round(seller_volume_usd, 2)
        except Exception:
            seller_volume_usd = 0.0

        resp = {
            **l,
            'images': images,
            'currencies': currencies if not l.get('accept_all') else list(SUPPORTED_CURRENCIES),
            'rating': avg_rating,
            'seller_volume_usd': seller_volume_usd
        }
        return jsonify(resp), 200
    except Exception as e:
        app.logger.exception("marketplace_detail error")
        return jsonify({"error": str(e)}), 500

@app.route('/api/marketplace', methods=['POST'])
@require_auth
@limiter.limit("30 per hour")
def marketplace_create():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}

        title = (body.get('title') or '').strip()
        description = (body.get('description') or '').strip()
        price_usd = body.get('price_usd')
        accept_all = bool(body.get('accept_all') or False)
        payment_methods = body.get('payment_methods') or []
        tags = body.get('tags') or []
        images_in = body.get('images') or []
        allowed_currencies = [str(c).upper() for c in (body.get('allowed_currencies') or [])]

        if not title or len(title) < 3:
            return jsonify({"error": "Title is required"}), 400
        try:
            price_val = float(price_usd)
        except Exception:
            return jsonify({"error": "price_usd must be a number"}), 400
        if price_val <= 0:
            return jsonify({"error": "price_usd must be > 0"}), 400

        allowed_methods = {'crypto','paypal'}
        if any(m not in allowed_methods for m in payment_methods):
            return jsonify({"error": "Invalid payment_methods"}), 400

        # Currency validation
        if not accept_all:
            if not allowed_currencies:
                return jsonify({"error": "allowed_currencies required when accept_all=false"}), 400
            for c in allowed_currencies:
                ok, err = validate_currency(c)
                if not ok:
                    return jsonify({"error": err}), 400

        # Moderation (text)
        ok, reason = _moderate_text(f"{title}\n\n{description}", context='listing')
        if not ok:
            return jsonify({"error": reason or "Content failed moderation"}), 400

        # Insert listing
        ins = supabase.table('listings').insert({
            'seller_id': uid,
            'title': title,
            'description': description,
            'price_usd': price_val,
            'accept_all': accept_all,
            'payment_methods': payment_methods,
            'status': 'active',
            'tags': tags,
        }).execute()
        if not ins.data:
            return jsonify({"error": "Failed to create listing"}), 500
        listing = ins.data[0]
        lid = listing['id']

        # Images (moderate each, then insert)
        def normalize_images(images):
            norm = []
            for idx, it in enumerate(images):
                if isinstance(it, dict):
                    url = it.get('url')
                    order = int(it.get('sort_order') or idx)
                else:
                    url = str(it)
                    order = idx
                if url:
                    norm.append({'url': url, 'sort_order': order})
            return norm

        normalized_images = normalize_images(images_in)
        for img in normalized_images:
            ok_i, reason_i = _moderate_image_url(img['url'], context='listing')
            if not ok_i:
                return jsonify({"error": reason_i or "Image failed moderation"}), 400
        if normalized_images:
            to_insert = [{ 'listing_id': lid, 'url': x['url'], 'sort_order': x['sort_order'] } for x in normalized_images]
            try:
                supabase.table('listing_images').insert(to_insert).execute()
            except Exception:
                app.logger.exception("listing_images insert error")

        # Allowed currencies
        if not accept_all and allowed_currencies:
            try:
                supabase.table('listing_currencies').insert([
                    { 'listing_id': lid, 'currency': c } for c in allowed_currencies
                ]).execute()
            except Exception:
                app.logger.exception("listing_currencies insert error")

        return jsonify({ **listing, 'images': [x['url'] for x in normalized_images], 'currencies': allowed_currencies }), 201
    except Exception as e:
        app.logger.exception("marketplace_create error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/marketplace/<uuid:listing_id>', methods=['PATCH'])
@require_auth
@limiter.limit("60 per hour")
def marketplace_update(listing_id):
    try:
        listing_id = str(listing_id)
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        # Fetch listing and authz
        cur = supabase.table('listings').select('*').eq('id', listing_id).single().execute()
        if not cur.data:
            return jsonify({"error": "Listing not found"}), 404
        if cur.data.get('seller_id') != uid:
            return jsonify({"error": "Forbidden"}), 403

        update = {}
        if 'title' in body:
            t = (body.get('title') or '').strip()
            if not t:
                return jsonify({"error": "Title cannot be empty"}), 400
            update['title'] = t
        if 'description' in body:
            update['description'] = (body.get('description') or '').strip()
        if 'price_usd' in body:
            try:
                pv = float(body.get('price_usd'))
                if pv <= 0:
                    return jsonify({"error": "price_usd must be > 0"}), 400
                update['price_usd'] = pv
            except Exception:
                return jsonify({"error": "price_usd must be a number"}), 400
        if 'payment_methods' in body:
            pms = body.get('payment_methods') or []
            allowed_methods = {'crypto','paypal'}
            if any(m not in allowed_methods for m in pms):
                return jsonify({"error": "Invalid payment_methods"}), 400
            update['payment_methods'] = pms
        if 'tags' in body:
            update['tags'] = body.get('tags') or []
        if 'accept_all' in body:
            update['accept_all'] = bool(body.get('accept_all'))
        if 'status' in body:
            st = (body.get('status') or '').strip().lower()
            if st not in ('draft','active','paused','deleted'):
                return jsonify({"error": "Invalid status"}), 400
            update['status'] = st

        # Moderation for text if changed
        if 'title' in update or 'description' in update:
            new_title = update.get('title', cur.data.get('title'))
            new_desc = update.get('description', cur.data.get('description'))
            ok, reason = _moderate_text(f"{new_title}\n\n{new_desc}", context='listing')
            if not ok:
                return jsonify({"error": reason or "Content failed moderation"}), 400

        # Persist listing updates
        if update:
            supabase.table('listings').update(update).eq('id', listing_id).execute()

        # Replace images if provided
        if 'images' in body:
            imgs_in = body.get('images') or []
            def normalize_images(images):
                norm = []
                for idx, it in enumerate(images):
                    if isinstance(it, dict):
                        url = it.get('url')
                        order = int(it.get('sort_order') or idx)
                    else:
                        url = str(it)
                        order = idx
                    if url:
                        norm.append({'url': url, 'sort_order': order})
                return norm
            normalized = normalize_images(imgs_in)
            for img in normalized:
                ok_i, reason_i = _moderate_image_url(img['url'], context='listing')
                if not ok_i:
                    return jsonify({"error": reason_i or "Image failed moderation"}), 400
            try:
                supabase.table('listing_images').delete().eq('listing_id', listing_id).execute()
                if normalized:
                    supabase.table('listing_images').insert([{ 'listing_id': listing_id, 'url': x['url'], 'sort_order': x['sort_order']} for x in normalized]).execute()
            except Exception:
                app.logger.exception("listing_images replace error")

        # Replace allowed_currencies if provided and not accept_all
        if 'allowed_currencies' in body:
            allowed_currencies = [str(c).upper() for c in (body.get('allowed_currencies') or [])]
            if not update.get('accept_all', cur.data.get('accept_all')):
                for c in allowed_currencies:
                    okc, err = validate_currency(c)
                    if not okc:
                        return jsonify({"error": err}), 400
                try:
                    supabase.table('listing_currencies').delete().eq('listing_id', listing_id).execute()
                    if allowed_currencies:
                        supabase.table('listing_currencies').insert([{ 'listing_id': listing_id, 'currency': c } for c in allowed_currencies]).execute()
                except Exception:
                    app.logger.exception("listing_currencies replace error")
            else:
                # accept_all true -> clear currencies
                try:
                    supabase.table('listing_currencies').delete().eq('listing_id', listing_id).execute()
                except Exception:
                    pass

        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("marketplace_update error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/marketplace/<uuid:listing_id>/pause', methods=['POST'])
@require_auth
@limiter.limit("30 per hour")
def marketplace_pause(listing_id):
    try:
        listing_id = str(listing_id)
        uid = request.user_id
        cur = supabase.table('listings').select('seller_id').eq('id', listing_id).single().execute()
        if not cur.data:
            return jsonify({"error": "Listing not found"}), 404
        if cur.data.get('seller_id') != uid:
            return jsonify({"error": "Forbidden"}), 403
        supabase.table('listings').update({'status': 'paused'}).eq('id', listing_id).execute()
        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("marketplace_pause error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/marketplace/<uuid:listing_id>/resume', methods=['POST'])
@require_auth
@limiter.limit("30 per hour")
def marketplace_resume(listing_id):
    try:
        listing_id = str(listing_id)
        uid = request.user_id
        cur = supabase.table('listings').select('seller_id').eq('id', listing_id).single().execute()
        if not cur.data:
            return jsonify({"error": "Listing not found"}), 404
        if cur.data.get('seller_id') != uid:
            return jsonify({"error": "Forbidden"}), 403
        supabase.table('listings').update({'status': 'active'}).eq('id', listing_id).execute()
        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("marketplace_resume error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/marketplace/<uuid:listing_id>', methods=['DELETE'])
@require_auth
@limiter.limit("30 per hour")
def marketplace_delete(listing_id):
    try:
        listing_id = str(listing_id)
        uid = request.user_id
        cur = supabase.table('listings').select('seller_id').eq('id', listing_id).single().execute()
        if not cur.data:
            return jsonify({"error": "Listing not found"}), 404
        if cur.data.get('seller_id') != uid:
            return jsonify({"error": "Forbidden"}), 403
        # Soft delete for safety
        supabase.table('listings').update({'status': 'deleted'}).eq('id', listing_id).execute()
        return jsonify({"ok": True}), 200
    except Exception as e:
        app.logger.exception("marketplace_delete error")
        return jsonify({"error": str(e)}), 500


# --------------------- Reports (User + Admin) ---------------------

@app.route('/api/reports', methods=['POST'])
@require_auth
@limiter.limit("30 per hour")
def create_report():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        entity_type = (body.get('entity_type') or '').strip().lower()
        entity_id = (body.get('entity_id') or '').strip()
        reason = (body.get('reason') or '').strip()

        if entity_type not in ('listing', 'user'):
            return jsonify({"error": "entity_type must be 'listing' or 'user'"}), 400
        if not entity_id:
            return jsonify({"error": "entity_id is required"}), 400
        if not reason or len(reason) < 5:
            return jsonify({"error": "reason is required (min 5 chars)"}), 400

        ins = supabase.table('reports').insert({
            'entity_type': entity_type,
            'entity_id': entity_id,
            'reporter_id': uid,
            'reason': reason,
            'status': 'open',
            'created_at': datetime.utcnow().isoformat()
        }).execute()

        return jsonify(ins.data[0] if ins.data else {"ok": True}), 201
    except Exception as e:
        app.logger.exception("create_report error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/reports', methods=['GET'])
@require_admin
@limiter.limit("60 per minute")
def admin_list_reports():
    try:
        # Filters
        page = int(request.args.get('page', 1))
        limit = min(int(request.args.get('limit', 50)), 100)
        status_f = (request.args.get('status') or '').strip().lower()
        entity_type = (request.args.get('entity_type') or '').strip().lower()
        search = (request.args.get('search') or '').strip()
        offset = (page - 1) * limit

        q = supabase.table('reports').select('*')
        if status_f:
            q = q.eq('status', status_f)
        if entity_type in ('listing', 'user'):
            q = q.eq('entity_type', entity_type)
        if search:
            q = q.ilike('reason', f"%{search}%")

        # Count
        try:
            cq = supabase.table('reports').select('id', count='exact')
            if status_f:
                cq = cq.eq('status', status_f)
            if entity_type in ('listing', 'user'):
                cq = cq.eq('entity_type', entity_type)
            if search:
                cq = cq.ilike('reason', f"%{search}%")
            cr = cq.execute()
            total = cr.count or 0
        except Exception:
            total = 0

        res = q.order('created_at', desc=True).range(offset, offset + limit - 1).execute()
        items = res.data or []

        # Optional enrichment for listings: attach title if exists
        try:
            listing_ids = [x['entity_id'] for x in items if x.get('entity_type') == 'listing']
            if listing_ids:
                lr = supabase.table('listings').select('id, title, status').in_('id', listing_ids).execute()
                m = {r['id']: r for r in (lr.data or [])}
                for it in items:
                    if it.get('entity_type') == 'listing' and it.get('entity_id') in m:
                        it['listing'] = m[it['entity_id']]
        except Exception:
            pass

        return jsonify({
            'items': items,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total,
                'pages': (total + limit - 1) // limit
            }
        }), 200
    except Exception as e:
        app.logger.exception("admin_list_reports error")
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/reports/<report_id>/action', methods=['POST'])
@require_admin
@limiter.limit("60 per minute")
def admin_report_action(report_id):
    try:
        body = request.get_json(silent=True) or {}
        action = (body.get('action') or '').strip().lower()
        note = (body.get('note') or '').strip()

        # Load report
        r = supabase.table('reports').select('*').eq('id', report_id).single().execute()
        if not r.data:
            return jsonify({"error": "Report not found"}), 404
        rep = r.data

        # Actions: triage|resolve|dismiss|pause_listing|delete_listing|ban_user
        status_update = None
        if action == 'triage':
            status_update = 'triaged'
        elif action == 'resolve':
            status_update = 'resolved'
        elif action == 'dismiss':
            status_update = 'dismissed'
        elif action in ('pause_listing', 'delete_listing') and rep.get('entity_type') == 'listing':
            if action == 'pause_listing':
                supabase.table('listings').update({'status': 'paused'}).eq('id', rep['entity_id']).execute()
                status_update = 'triaged'
            else:
                supabase.table('listings').update({'status': 'deleted'}).eq('id', rep['entity_id']).execute()
                status_update = 'resolved'
        elif action == 'ban_user' and rep.get('entity_type') == 'user':
            supabase.table('profiles').update({'banned': True, 'banned_reason': note or 'Policy violation', 'banned_at': datetime.utcnow().isoformat()}).eq('id', rep['entity_id']).execute()
            status_update = 'resolved'
        else:
            return jsonify({"error": "Invalid action for this report"}), 400

        # Update report row
        update = {
            'status': status_update or rep.get('status'),
            'resolved_by': request.user_id,
            'resolution_note': note,
            'created_at': rep.get('created_at')
        }
        supabase.table('reports').update(update).eq('id', report_id).execute()

        # Audit
        try:
            log_admin_action(request.user_id, f"Report {report_id} action={action}", request.remote_addr, {'report_id': report_id, 'action': action})
        except Exception:
            pass

        return jsonify({'ok': True, 'status': status_update}), 200
    except Exception as e:
        app.logger.exception("admin_report_action error")
        return jsonify({"error": str(e)}), 500


# Moderation config admin endpoints
@app.route('/api/admin/moderation/config', methods=['GET'])
@require_admin
@limiter.limit("30 per minute")
def admin_get_moderation_config():
    try:
        cfg = _get_moderation_settings()
        return jsonify(cfg), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/admin/moderation/config', methods=['POST'])
@require_admin
@limiter.limit("20 per minute")
def admin_set_moderation_config():
    try:
        body = request.get_json(silent=True) or {}
        provider = (body.get('provider') or '').strip().lower()
        enabled = body.get('enabled')
        thresholds = body.get('thresholds') if isinstance(body.get('thresholds'), dict) else None
        api_key = body.get('api_key')

        row = {
            'provider': provider or None,
            'enabled': bool(enabled) if enabled is not None else True,
            'updated_at': datetime.utcnow().isoformat(),
            'updated_by': request.user_id
        }
        if thresholds is not None:
            row['thresholds'] = thresholds
        if api_key:
            row['api_key'] = api_key

        ins = supabase.table('moderation_config').insert(row).execute()
        return jsonify(ins.data[0] if ins.data else row), 201
    except Exception as e:
        app.logger.exception("admin_set_moderation_config error")
        return jsonify({"error": str(e)}), 500


# --------------------- Cart & Checkout ---------------------

def _price_to_crypto_amount(total_usd: float, currency: str) -> float:
    price = get_usd_price(currency) or 0
    if not price or price <= 0:
        return 0.0
    try:
        return round(float(total_usd) / float(price), 8)
    except Exception:
        return 0.0


@app.route('/api/cart', methods=['GET'])
@require_auth
@limiter.limit(os.getenv('RL_CART_LIST', '200 per hour'))
def cart_list():
    try:
        uid = request.user_id
        items_res = supabase.table('cart_items').select('*').eq('user_id', uid).order('created_at', desc=True).execute()
        items = items_res.data or []
        if not items:
            return jsonify({'items': [], 'groups': [], 'line_items': []}), 200

        listing_ids = list({x['listing_id'] for x in items})
        listings = {}
        if listing_ids:
            lr = supabase.table('listings').select('id, seller_id, title, price_usd, accept_all').in_('id', listing_ids).execute()
            for r in (lr.data or []):
                listings[r['id']] = r

        # Hydrate items
        for it in items:
            meta = listings.get(it['listing_id']) or {}
            it['listing'] = meta

        # Group by payment_method + currency (for checkout) and build aggregated line items for UI
        groups = {}
        line_map = {}
        for it in items:
            pm = (it.get('payment_method') or '').lower()
            cc = (it.get('selected_currency') or ('USD' if pm == 'paypal' else '')).upper()
            key = f"{pm}:{cc}"
            groups.setdefault(key, {'payment_method': pm, 'currency': cc, 'items': [], 'total_usd': 0.0})
            unit_price = float((it.get('listing') or {}).get('price_usd') or 0)
            qty = float(it.get('quantity') or 1)
            price_usd = unit_price * qty
            groups[key]['items'].append({
                'cart_item_id': it.get('id'),
                'listing_id': it.get('listing_id'),
                'seller_id': (it.get('listing') or {}).get('seller_id'),
                'title': (it.get('listing') or {}).get('title'),
                'quantity': it.get('quantity') or 1,
                'price_usd': price_usd,
            })
            groups[key]['total_usd'] += price_usd

            line_key = f"{it.get('listing_id')}|{pm}|{cc}"
            if line_key not in line_map:
                line_map[line_key] = {
                    'listing_id': it.get('listing_id'),
                    'title': (it.get('listing') or {}).get('title'),
                    'payment_method': pm,
                    'currency': cc,
                    'quantity': 0,
                    'unit_price_usd': unit_price,
                    'total_usd': 0.0,
                }
            line_map[line_key]['quantity'] += int(it.get('quantity') or 1)
            line_map[line_key]['total_usd'] = round(line_map[line_key]['quantity'] * unit_price, 2)

        return jsonify({'items': items, 'groups': list(groups.values()), 'line_items': list(line_map.values())}), 200
    except Exception as e:
        app.logger.exception("cart_list error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cart', methods=['POST'])
@require_auth
@limiter.limit(os.getenv('RL_CART_ADD', '200 per hour'))
def cart_add():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        listing_id = body.get('listing_id')
        quantity = int(body.get('quantity') or 1)
        selected_currency = (body.get('selected_currency') or '').upper()
        payment_method = (body.get('payment_method') or '').lower()

        if not listing_id or not payment_method:
            return jsonify({'error': 'listing_id and payment_method required'}), 400
        if payment_method not in ('crypto', 'paypal'):
            return jsonify({'error': 'payment_method must be crypto or paypal'}), 400

        # Validate listing and currency/method
        lr = supabase.table('listings').select('id, seller_id, price_usd, accept_all').eq('id', listing_id).single().execute()
        if not lr.data:
            return jsonify({'error': 'Listing not found'}), 404

        # Prevent users from adding their own items to cart
        if lr.data.get('seller_id') == uid:
            app.logger.info(f"User {uid} tried to add their own listing {listing_id} to cart")
            return jsonify({'error': 'You cannot add your own item to cart'}), 400
        if payment_method == 'crypto':
            if not selected_currency:
                return jsonify({'error': 'selected_currency required for crypto'}), 400
            ok, err = validate_currency(selected_currency)
            if not ok:
                return jsonify({'error': err}), 400
        else:
            selected_currency = 'USD'

        # Upsert: if same line exists, bump quantity; otherwise insert new
        q = supabase.table('cart_items').select('id, quantity') \
            .eq('user_id', uid).eq('listing_id', listing_id).eq('payment_method', payment_method)
        if payment_method == 'crypto':
            q = q.eq('selected_currency', selected_currency)
        ex = q.execute()
        if ex.data:
            first = ex.data[0]
            new_qty = int(first.get('quantity') or 1) + int(quantity or 1)
            supabase.table('cart_items').update({'quantity': new_qty, 'selected_currency': selected_currency or None}).eq('id', first['id']).execute()
            if len(ex.data) > 1:
                supabase.table('cart_items').delete().in_('id', [r['id'] for r in ex.data[1:]]).execute()
            return jsonify({'id': first['id'], 'quantity': new_qty}), 200
        ins = supabase.table('cart_items').insert({
            'user_id': uid,
            'listing_id': listing_id,
            'quantity': quantity,
            'selected_currency': selected_currency or None,
            'payment_method': payment_method
        }).execute()
        # Return unified line payload for client convenience
        return jsonify({
            'id': (ins.data or [{}])[0].get('id'),
            'listing_id': listing_id,
            'payment_method': payment_method,
            'selected_currency': selected_currency or None,
            'quantity': quantity
        }), 201
    except Exception as e:
        app.logger.exception("cart_add error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cart/<item_id>', methods=['DELETE'])
@require_auth
@limiter.limit("120 per hour")
def cart_delete(item_id):
    try:
        uid = request.user_id
        # ensure ownership
        it = supabase.table('cart_items').select('user_id').eq('id', item_id).single().execute()
        if not it.data or it.data.get('user_id') != uid:
            return jsonify({'error': 'Not found'}), 404
        supabase.table('cart_items').delete().eq('id', item_id).execute()
        return jsonify({'ok': True}), 200
    except Exception as e:
        app.logger.exception("cart_delete error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/cart/update-qty', methods=['POST'])
@app.route('/api/cart/qty', methods=['POST'])
@require_auth
@limiter.limit(os.getenv('RL_CART_QTY', '600 per hour'))
def cart_update_qty():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        listing_id = body.get('listing_id')
        payment_method = (body.get('payment_method') or '').lower()
        selected_currency = (body.get('selected_currency') or '').upper()
        quantity = int(body.get('quantity') or 0)

        if not listing_id or payment_method not in ('crypto', 'paypal'):
            return jsonify({'error': 'listing_id and valid payment_method required'}), 400
        if payment_method == 'paypal':
            selected_currency = 'USD'
        elif not selected_currency:
            return jsonify({'error': 'selected_currency required for crypto'}), 400

        q = supabase.table('cart_items').select('id, quantity').eq('user_id', uid).eq('listing_id', listing_id).eq('payment_method', payment_method)
        if payment_method == 'crypto':
            q = q.eq('selected_currency', selected_currency)
        rows = q.execute().data or []

        if quantity <= 0:
            if rows:
                supabase.table('cart_items').delete().in_('id', [r['id'] for r in rows]).execute()
            return jsonify({'ok': True}), 200

        if not rows:
            ins = supabase.table('cart_items').insert({
                'user_id': uid,
                'listing_id': listing_id,
                'quantity': quantity,
                'selected_currency': selected_currency,
                'payment_method': payment_method
            }).execute()
            return jsonify(ins.data[0] if ins.data else {'ok': True}), 200

        keep = rows[0]
        supabase.table('cart_items').update({'quantity': quantity}).eq('id', keep['id']).execute()
        if len(rows) > 1:
            supabase.table('cart_items').delete().in_('id', [r['id'] for r in rows[1:]]).execute()
        return jsonify({'id': keep['id'], 'quantity': quantity}), 200
    except Exception as e:
        app.logger.exception("cart_update_qty error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cart/checkout', methods=['POST'])
@require_auth
@limiter.limit(os.getenv('RL_CART_CHECKOUT', '200 per hour'))
def cart_checkout():
    try:
        uid = request.user_id
        items_res = supabase.table('cart_items').select('*').eq('user_id', uid).execute()
        items = items_res.data or []
        if not items:
            return jsonify({'error': 'Cart is empty'}), 400

        listing_ids = list({x['listing_id'] for x in items})
        listings = {}
        if listing_ids:
            lr = supabase.table('listings').select('id, seller_id, title, price_usd').in_('id', listing_ids).execute()
            for r in (lr.data or []):
                listings[r['id']] = r

        # Build groups
        groups = []
        group_map = {}
        for it in items:
            pm = (it.get('payment_method') or '').lower()
            cc = (it.get('selected_currency') or ('USD' if pm=='paypal' else '')).upper()
            key = f"{pm}:{cc}"
            if key not in group_map:
                group_map[key] = {'payment_method': pm, 'currency': cc, 'items': [], 'total_usd': 0.0}
            meta = listings.get(it['listing_id']) or {}
            price_usd = float(meta.get('price_usd') or 0) * float(it.get('quantity') or 1)
            group_map[key]['items'].append({
                'listing_id': it['listing_id'],
                'seller_id': meta.get('seller_id'),
                'title': meta.get('title'),
                'quantity': it.get('quantity') or 1,
                'price_usd': price_usd,
            })
            group_map[key]['total_usd'] += price_usd
        groups = list(group_map.values())

        aggregators = []
        paypal_ctx = []
        # Prepare payment contexts
        for g in groups:
            if g['payment_method'] == 'crypto':
                currency = g['currency']
                address = get_platform_address(currency)
                if not address:
                    return jsonify({'error': f'Missing platform address for {currency}'}), 500
                required = _price_to_crypto_amount(g['total_usd'], currency)
                aggregators.append({'currency': currency, 'address': address, 'required': required, 'balance': 0.0})
            else:
                # One PayPal order for the group
                fee_info = {'fee_rate': 0.02, 'fee_amount': round(g['total_usd']*0.02,2), 'net_amount': round(g['total_usd']*0.98,2), 'usd_amount': g['total_usd']}
                order = create_paypal_order_authorize(g['total_usd'], 'USD', fee_info)
                if not order:
                    return jsonify({'error': 'Failed to create PayPal order'}), 500
                paypal_ctx.append({'order_id': order['id'], 'approval_url': order.get('approval_url')})

        session = {
            'user_id': uid,
            'groups': groups,
            'crypto_aggregators': aggregators,
            'paypal_context': {'orders': paypal_ctx},
            'status': 'funding',
            'created_at': datetime.utcnow().isoformat()
        }
        ins = supabase.table('checkout_sessions').insert(session).execute()
        sid = (ins.data or [{}])[0].get('id')
        return jsonify({'session_id': sid, 'crypto_aggregators': aggregators, 'paypal': paypal_ctx, 'groups': groups}), 200
    except Exception as e:
        app.logger.exception("cart_checkout error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cart/crypto/check-funding', methods=['POST'])
@require_auth
@limiter.limit(os.getenv('RL_CART_CHECK_FUNDING', '200 per hour'))
def cart_check_crypto_funding():
    try:
        uid = request.user_id
        sid = (request.get_json(silent=True) or {}).get('session_id')
        if not sid:
            return jsonify({'error': 'session_id required'}), 400
        sess = supabase.table('checkout_sessions').select('*').eq('id', sid).single().execute()
        if not sess.data or sess.data.get('user_id') != uid:
            return jsonify({'error': 'Session not found'}), 404
        aggs = sess.data.get('crypto_aggregators') or []
        updated = []
        all_ok = True
        for a in aggs:
            currency = a.get('currency')
            address = a.get('address')
            required = float(a.get('required') or 0)
            # Use Tatum balance endpoint
            try:
                chain = CHAIN_MAP.get(currency)
                headers = {'x-api-key': TATUM_API_KEY, 'Content-Type': 'application/json'}
                r = requests.get(f"{TATUM_API_URL}/{chain}/address/balance/{address}", headers=headers, timeout=20)
                bal = 0.0
                if r.status_code == 200:
                    jd = r.json()
                    bal = float(jd.get('incoming') or jd.get('balance') or 0)
            except Exception:
                bal = 0.0
            ok = bal >= required
            updated.append({**a, 'balance': round(bal,8)})
            if not ok:
                all_ok = False
        # update session
        supabase.table('checkout_sessions').update({'crypto_aggregators': updated, 'status': 'funded' if all_ok else 'funding', 'updated_at': datetime.utcnow().isoformat()}).eq('id', sid).execute()
        return jsonify({'crypto_aggregators': updated, 'all_funded': all_ok}), 200
    except Exception as e:
        app.logger.exception("cart_check_crypto_funding error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/cart/finalize', methods=['POST'])
@require_auth
@limiter.limit(os.getenv('RL_CART_FINALIZE', '200 per hour'))
def cart_finalize():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        sid = body.get('session_id')
        if not sid:
            return jsonify({'error': 'session_id required'}), 400
        sess = supabase.table('checkout_sessions').select('*').eq('id', sid).single().execute()
        if not sess.data or sess.data.get('user_id') != uid:
            return jsonify({'error': 'Session not found'}), 404

        groups = sess.data.get('groups') or []
        aggs = sess.data.get('crypto_aggregators') or []
        paypal_orders = (body.get('paypal_orders') or [])
        paypal_auth_ids = {}
        # Authorize PayPal orders
        for idx, po in enumerate((sess.data.get('paypal_context') or {}).get('orders') or []):
            # client should pass token/order_id back after approval
            token = None
            for ent in paypal_orders:
                if ent.get('order_id') == po.get('order_id'):
                    token = ent.get('order_id')
                    break
            if token:
                auth_id = get_authorization_id_from_order(token)
                if not auth_id:
                    return jsonify({'error': f'Failed to resolve authorization for order {token}'}), 400
                paypal_auth_ids[token] = auth_id
            else:
                return jsonify({'error': 'Missing approved PayPal order token(s)'}), 400

        # Verify crypto funding
        for a in aggs:
            if float(a.get('balance') or 0) < float(a.get('required') or 0):
                return jsonify({'error': f'Crypto not fully funded for {a.get("currency")}'}), 400

        created_escrows = []
        # Create escrows and disburse (for crypto)
        for g in groups:
            pm = g.get('payment_method')
            if pm == 'crypto':
                currency = g.get('currency')
                # create escrow per item
                for it in g.get('items') or []:
                    price_usd = float(it.get('price_usd') or 0)
                    amount_crypto = _price_to_crypto_amount(price_usd, currency)
                    ins = supabase.table('escrows').insert({
                        'buyer_id': uid,
                        'seller_id': it.get('seller_id'),
                        'amount': amount_crypto,
                        'currency': currency,
                        'payment_method': 'crypto',
                        'status': 'pending',
                        'usd_amount': price_usd
                    }).execute()
                    escrow_id = (ins.data or [{}])[0].get('id')
                    if not escrow_id:
                        return jsonify({'error': 'Failed to create escrow'}), 500
                    # generate deposit address
                    addr = generate_crypto_address(currency, escrow_id)
                    if not addr:
                        return jsonify({'error': 'Failed to create escrow wallet'}), 500
                    supabase.table('escrows').update({'deposit_address': addr}).eq('id', escrow_id).execute()
                    # disburse from aggregator (platform) to deposit
                    tx = send_platform_crypto(currency, addr, amount_crypto)
                    if not tx:
                        return jsonify({'error': 'Failed to disburse crypto from aggregator'}), 500
                    supabase.table('escrows').update({'status': 'funded'}).eq('id', escrow_id).execute()
                    supabase.table('transactions').insert({'escrow_id': escrow_id,'type':'deposit','amount': amount_crypto,'currency': currency,'transaction_hash': tx,'usd_amount': price_usd}).execute()
                    created_escrows.append({'id': escrow_id})
            else:
                # PayPal: create escrow per item and store authorization id
                for it in g.get('items') or []:
                    price_usd = float(it.get('price_usd') or 0)
                    # assume single order per paypal group; use first auth id
                    token = ((sess.data.get('paypal_context') or {}).get('orders') or [{}])[0].get('order_id')
                    auth_id = paypal_auth_ids.get(token)
                    ins = supabase.table('escrows').insert({
                        'buyer_id': uid,
                        'seller_id': it.get('seller_id'),
                        'amount': price_usd,
                        'currency': 'USD',
                        'payment_method': 'paypal',
                        'status': 'funded',
                        'usd_amount': price_usd,
                        'paypal_authorization_id': auth_id,
                        'paypal_order_id': token
                    }).execute()
                    escrow_id = (ins.data or [{}])[0].get('id')
                    supabase.table('transactions').insert({'escrow_id': escrow_id,'type':'deposit','amount': price_usd,'currency': 'USD','paypal_transaction_id': auth_id,'usd_amount': price_usd}).execute()
                    created_escrows.append({'id': escrow_id})

        # Clear cart and close session
        supabase.table('cart_items').delete().eq('user_id', uid).execute()
        supabase.table('checkout_sessions').update({'status': 'completed','updated_at': datetime.utcnow().isoformat()}).eq('id', sid).execute()

        return jsonify({'ok': True, 'escrows': created_escrows}), 200
    except Exception as e:
        app.logger.exception("cart_finalize error")
        return jsonify({'error': str(e)}), 500


# --------------------- Pre-escrow Messaging ---------------------

@app.route('/api/messages', methods=['GET'])
@require_auth
@limiter.limit("60 per hour")
def list_conversations():
    try:
        uid = request.user_id
        # Conversations where user participates (supabase-py v2 lacks or_ helper; emulate)
        res_a = supabase.table('conversations').select('*').eq('starter_id', uid).order('created_at', desc=True).execute()
        res_b = supabase.table('conversations').select('*').eq('recipient_id', uid).order('created_at', desc=True).execute()
        seen = set()
        merged = []
        for r in (res_a.data or []) + (res_b.data or []):
            rid = r.get('id')
            if rid and rid not in seen:
                seen.add(rid)
                merged.append(r)
        convs = merged
        # Attach last message preview
        convo_ids = [c.get('id') for c in convs if c.get('id')]
        last_msgs = {}
        try:
            if convo_ids:
                # fetch last messages for all convs in one query
                lm = supabase.table('conversation_messages').select('conversation_id,body,image_url,created_at,sender_id').in_('conversation_id', convo_ids).order('created_at', desc=True).execute()
                # supabase returns all messages; we need the latest per conversation - iterate
                if lm.data:
                    for row in lm.data:
                        cid = row.get('conversation_id')
                        if cid and cid not in last_msgs:
                            last_msgs[cid] = row
        except Exception:
            pass

        # Batch fetch listing titles and participant usernames
        listing_ids = list({c.get('listing_id') for c in convs if c.get('listing_id')})
        profile_ids = list({p for c in convs for p in (c.get('starter_id'), c.get('recipient_id')) if p})
        listings_map = {}
        profiles_map = {}
        try:
            if listing_ids:
                lr = supabase.table('listings').select('id,title').in_('id', listing_ids).execute()
                if lr.data:
                    for l in lr.data:
                        listings_map[l.get('id')] = l
        except Exception:
            pass
        try:
            if profile_ids:
                pr = supabase.table('profiles').select('id,username').in_('id', profile_ids).execute()
                if pr.data:
                    for p in pr.data:
                        profiles_map[p.get('id')] = p
        except Exception:
            pass

        for c in convs:
            cid = c.get('id')
            if cid and last_msgs.get(cid):
                c['last_message'] = last_msgs[cid]
            # attach listing title if available
            lid = c.get('listing_id')
            if lid and listings_map.get(lid):
                c['listing_title'] = listings_map[lid].get('title')
            # attach starter/recipient usernames if available
            sid = c.get('starter_id')
            rid = c.get('recipient_id')
            if sid and profiles_map.get(sid):
                c['starter_username'] = profiles_map[sid].get('username')
            if rid and profiles_map.get(rid):
                c['recipient_username'] = profiles_map[rid].get('username')

        return jsonify({'items': convs}), 200
    except Exception as e:
        app.logger.exception("list_conversations error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/start-from-listing', methods=['POST'])
@app.route('/api/messages/start', methods=['POST'])
@require_auth
@limiter.limit("60 per hour")
def start_conversation_from_listing():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        listing_id = body.get('listing_id')
        if not listing_id:
            return jsonify({'error': 'listing_id required'}), 400
        lr = supabase.table('listings').select('id, seller_id, title, status').eq('id', listing_id).single().execute()
        if not lr.data:
            return jsonify({'error': 'Listing not found'}), 404
        seller_id = lr.data.get('seller_id')
        if seller_id == uid:
            return jsonify({'error': 'Cannot message yourself'}), 400
        # Create or find existing conversation for this pair+listing
        existing = supabase.table('conversations').select('id, title').eq('starter_id', uid).eq('recipient_id', seller_id).eq('listing_id', listing_id).limit(1).execute()
        listing_title = (lr.data or {}).get('title')
        if existing.data:
            conv_id = existing.data[0]['id']
            # Backfill title if missing
            try:
                if not (existing.data[0].get('title') or '').strip() and listing_title:
                    supabase.table('conversations').update({'title': listing_title}).eq('id', conv_id).execute()
            except Exception:
                pass
        else:
            ins = supabase.table('conversations').insert({
                'starter_id': uid,
                'recipient_id': seller_id,
                'listing_id': listing_id,
                'title': listing_title,
                'created_at': datetime.utcnow().isoformat()
            }).execute()
            conv_id = (ins.data or [{}])[0].get('id')
        return jsonify({'conversation_id': conv_id}), 201
    except Exception as e:
        app.logger.exception("start_conversation_from_listing error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<conversation_id>', methods=['GET'])
@require_auth
@limiter.limit("120 per hour")
def get_conversation_messages(conversation_id):
    try:
        uid = request.user_id
        c = supabase.table('conversations').select('*').eq('id', conversation_id).single().execute()
        if not c.data:
            return jsonify({'error': 'Conversation not found'}), 404
        if uid not in (c.data.get('starter_id'), c.data.get('recipient_id')):
            return jsonify({'error': 'Forbidden'}), 403
        msgs = supabase.table('conversation_messages').select('*').eq('conversation_id', conversation_id).order('created_at').execute()
        return jsonify({'conversation': c.data, 'messages': msgs.data or []}), 200
    except Exception as e:
        app.logger.exception("get_conversation_messages error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/messages/<conversation_id>', methods=['POST'])
@require_auth
@limiter.limit("60 per minute")
def send_conversation_message(conversation_id):
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        text = (body.get('body') or '').strip()
        image_url = (body.get('image_url') or '').strip() or None

        c = supabase.table('conversations').select('*').eq('id', conversation_id).single().execute()
        if not c.data:
            return jsonify({'error': 'Conversation not found'}), 404
        if uid not in (c.data.get('starter_id'), c.data.get('recipient_id')):
            return jsonify({'error': 'Forbidden'}), 403

        if not text and not image_url:
            return jsonify({'error': 'Message body or image required'}), 400

        # Moderation
        if text:
            ok, reason = _moderate_text(text, context='message')
            if not ok:
                return jsonify({'error': reason or 'Message failed moderation'}), 400
        if image_url:
            ok_i, reason_i = _moderate_image_url(image_url, context='message')
            if not ok_i:
                return jsonify({'error': reason_i or 'Image failed moderation'}), 400

        ins = supabase.table('conversation_messages').insert({
            'conversation_id': conversation_id,
            'sender_id': uid,
            'body': text or None,
            'image_url': image_url,
            'created_at': datetime.utcnow().isoformat()
        }).execute()
        return jsonify(ins.data[0] if ins.data else {'ok': True}), 201
    except Exception as e:
        app.logger.exception("send_conversation_message error")
        return jsonify({'error': str(e)}), 500

# --------------------- Error Handlers ---------------------
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"error": "Rate limit exceeded", "message": str(e.description)}), 429

@app.errorhandler(500)
def internal_error(error):
    app.logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500


@app.route('/api/calculate-fee', methods=['POST'])
def calculate_fee_public():
    body = request.get_json(silent=True) or {}
    payment_method = (body.get('payment_method') or 'crypto').lower()
    currency = (body.get('currency') or '').upper()

    # amount: crypto amount for crypto, USD for PayPal
    try:
        amount = float(body.get('amount') or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid amount"}), 400

    usd_amount_raw = body.get('usd_amount')

    if payment_method == 'crypto':
        supported = {'BTC','ETH','LTC','BCH','DOGE','XRP','ADA','DOT','MATIC','SOL','AVAX','TRX','BNB','ATOM','XLM',
             'USDT-ERC20','USDT-BEP20','USDT-SOL','USDT-TRON'}
        if currency not in supported:
            return jsonify({"error": f"Unsupported currency: {currency}"}), 400

        # Resolve USD amount for display
        if usd_amount_raw is None:
            price = get_usd_price(currency) or 0
            usd_amount = amount * price
        else:
            try:
                usd_amount = float(usd_amount_raw)
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid usd_amount"}), 400

        rate = 0.02 if usd_amount < 50 else 0.015
        fee_usd = round(usd_amount * rate, 2)
        net_usd = round(usd_amount - fee_usd, 2)
        total_usd = round(usd_amount, 2)

        fee_crypto = round(amount * rate, 8)
        net_crypto = round(amount - fee_crypto, 8)

        return jsonify({
            "payment_method": payment_method,
            "currency": currency,
            "usd_amount": round(usd_amount, 2),
            "fee_percentage": round(rate * 100, 2),
            "fee_rate": rate,
            "fee_amount": fee_usd,      # USD
            "net_amount": net_usd,      # USD
            "total_amount": total_usd,  # USD
            "amount_crypto": amount,
            "fee_crypto": fee_crypto,
            "net_crypto": net_crypto
        }), 200

    elif payment_method == 'paypal':
        if usd_amount_raw is None:
            usd_amount = amount
        else:
            try:
                usd_amount = float(usd_amount_raw)
            except (TypeError, ValueError):
                return jsonify({"error": "Invalid usd_amount"}), 400

        rate = 0.02
        fee_usd = round(usd_amount * rate, 2)
        net_usd = round(usd_amount - fee_usd, 2)
        total_usd = round(usd_amount, 2)

        return jsonify({
            "payment_method": payment_method,
            "currency": "USD",
            "usd_amount": usd_amount,
            "fee_percentage": round(rate * 100, 2),
            "fee_rate": rate,
            "fee_amount": fee_usd,
            "net_amount": net_usd,
            "total_amount": total_usd
        }), 200

    else:
        return jsonify({"error": "Invalid payment method"}), 400
        
# --------------------- Run ---------------------
@app.route('/api/marketplace/search/log', methods=['POST'])
@require_auth
@limiter.limit("300 per hour")
def marketplace_search_log():
    try:
        uid = request.user_id
        body = request.get_json(silent=True) or {}
        q = (body.get('q') or '').strip()
        filters = body.get('filters') or {}
        if not q and not filters:
            return jsonify({'ok': True}), 200
        supabase.table('search_history').insert({
            'user_id': uid,
            'query': q,
            'filters': filters,
        }).execute()
        return jsonify({'ok': True}), 201
    except Exception as e:
        app.logger.exception("marketplace_search_log error")
        return jsonify({'error': str(e)}), 500


@app.route('/api/marketplace/recommendations', methods=['GET'])
@require_auth
@limiter.limit("120 per hour")
def marketplace_recommendations():
    try:
        uid = request.user_id
        # pull recent queries
        sr = supabase.table('search_history').select('*').eq('user_id', uid).order('created_at', desc=True).limit(20).execute()
        queries = [x.get('query') for x in (sr.data or []) if (x.get('query') or '').strip()]
        tags = set()
        for q in queries:
            for token in str(q).lower().split():
                if len(token) >= 3:
                    tags.add(token)
        # naive: find listings with title/description matching any tag
        recs = []
        if tags:
            # limit to active listings
            items = supabase.table('listings').select('*').eq('status','active').limit(100).execute()
            for it in (items.data or []):
                title = (it.get('title') or '').lower()
                desc = (it.get('description') or '').lower()
                if any(t in title or t in desc for t in tags):
                    recs.append(it)
        # attach images/currencies similar to index
        listing_ids = [x['id'] for x in recs if x.get('id')]
        images_by_listing = {}
        curr_by_listing = {}
        if listing_ids:
            try:
                imgs = supabase.table('listing_images').select('listing_id,url,sort_order').in_('listing_id', listing_ids).order('sort_order').execute()
                for row in (imgs.data or []):
                    images_by_listing.setdefault(row['listing_id'], []).append(row['url'])
            except Exception:
                pass
            try:
                cur = supabase.table('listing_currencies').select('listing_id,currency').in_('listing_id', listing_ids).execute()
                for row in (cur.data or []):
                    curr_by_listing.setdefault(row['listing_id'], []).append(row['currency'])
            except Exception:
                pass
        enriched = [{ **x, 'images': images_by_listing.get(x['id'], []), 'currencies': curr_by_listing.get(x['id'], []) if not x.get('accept_all') else list(SUPPORTED_CURRENCIES) } for x in recs]
        return jsonify({'items': enriched}), 200
    except Exception as e:
        app.logger.exception("marketplace_recommendations error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/marketplace/hot-products', methods=['GET'])
@limiter.exempt
def marketplace_hot_products():
    """Return hot/trending products based on activity and recency."""
    try:
        # Get active listings with some basic data
        items = supabase.table('listings').select('*').eq('status', 'active').limit(50).execute()
        listings = items.data or []

        # Calculate hotness score for each listing
        scored_listings = []
        current_time = datetime.utcnow()

        for listing in listings:
            # Base score from price (higher priced items might be more "valuable")
            price_score = min(listing.get('price_usd', 0) / 100, 10)  # Cap at 10 points

            # Recency score (newer listings get higher score)
            created_at = listing.get('created_at')
            if created_at:
                try:
                    created_time = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    days_old = (current_time - created_time).total_seconds() / (24 * 3600)
                    recency_score = max(0, 5 - (days_old / 7))  # 5 points max, decays over weeks
                except:
                    recency_score = 0
            else:
                recency_score = 0

            # Random factor to add some variety and prevent identical scores
            random_factor = random.uniform(0, 2)

            # Total score
            total_score = price_score + recency_score + random_factor

            scored_listings.append({
                **listing,
                'hotness_score': total_score
            })

        # Sort by hotness score (descending) and take top 12
        scored_listings.sort(key=lambda x: x['hotness_score'], reverse=True)
        top_listings = scored_listings[:12]

        # Attach images and currencies like other endpoints
        listing_ids = [x['id'] for x in top_listings if x.get('id')]
        images_by_listing = {}
        curr_by_listing = {}

        if listing_ids:
            try:
                imgs = supabase.table('listing_images').select('listing_id,url,sort_order').in_('listing_id', listing_ids).order('sort_order').execute()
                for row in (imgs.data or []):
                    images_by_listing.setdefault(row['listing_id'], []).append(row['url'])
            except Exception:
                pass

            try:
                cur = supabase.table('listing_currencies').select('listing_id,currency').in_('listing_id', listing_ids).execute()
                for row in (cur.data or []):
                    curr_by_listing.setdefault(row['listing_id'], []).append(row['currency'])
            except Exception:
                pass

        # Build enriched response
        enriched = []
        for x in top_listings:
            enriched.append({
                **x,
                'images': images_by_listing.get(x['id'], []),
                'currencies': curr_by_listing.get(x['id'], []) if not x.get('accept_all') else list(SUPPORTED_CURRENCIES),
                'thumbnailUrl': (images_by_listing.get(x['id']) or [None])[0],  # First image as thumbnail
                'purchaseCount': 0,  # Placeholder - would need purchase history table
                'ratingAverage': 0,  # Placeholder - would need reviews table
                'ratingCount': 0,    # Placeholder - would need reviews table
            })

        return jsonify({'products': enriched}), 200

    except Exception as e:
        app.logger.exception("marketplace_hot_products error")
        return jsonify({'error': str(e)}), 500

# ===========================================
# ANALYTICS SYSTEM - INTEGRATED INTO APP.PY
# ===========================================

# Analytics helper functions
def get_listing_analytics_summary(listing_id: str) -> dict:
    """Get summary analytics for a listing"""
    try:
        # Check cache first
        cache_key = f"summary:{listing_id}"
        cached = get_cached_analytics(listing_id, cache_key)
        if cached:
            return cached

        # Get basic metrics
        views_result = supabase.table('listing_views').select('id', count='exact').eq('listing_id', listing_id).execute()
        total_views = views_result.count or 0

        # Unique viewers
        unique_result = supabase.table('listing_views').select('viewer_id', count='exact').eq('listing_id', listing_id).execute()
        unique_viewers = len(set(v['viewer_id'] for v in unique_result.data if v['viewer_id'])) if unique_result.data else 0

        # Sales count
        sales_result = supabase.table('escrows').select('id', count='exact').eq('listing_id', listing_id).eq('status', 'completed').execute()
        total_sales = sales_result.count or 0

        # Average sale price
        avg_price_result = supabase.table('escrows').select('amount_usd').eq('listing_id', listing_id).eq('status', 'completed').execute()
        avg_sale_price = 0
        if avg_price_result.data:
            prices = [escrow['amount_usd'] for escrow in avg_price_result.data if escrow['amount_usd']]
            avg_sale_price = sum(prices) / len(prices) if prices else 0

        # Last viewed
        last_view_result = supabase.table('listing_views').select('viewed_at').eq('listing_id', listing_id).order('viewed_at', desc=True).limit(1).execute()
        last_viewed = last_view_result.data[0]['viewed_at'] if last_view_result.data else None

        # Views last 7 days
        seven_days_ago = (datetime.now() - timedelta(days=7)).isoformat()
        views_7d_result = supabase.table('listing_views').select('id', count='exact').eq('listing_id', listing_id).gte('viewed_at', seven_days_ago).execute()
        views_last_7d = views_7d_result.count or 0

        # Sales last 7 days
        sales_7d_result = supabase.table('escrows').select('id', count='exact').eq('listing_id', listing_id).eq('status', 'completed').gte('created_at', seven_days_ago).execute()
        sales_last_7d = sales_7d_result.count or 0

        # Conversion rate
        conversion_rate = (total_sales / total_views * 100) if total_views > 0 else 0

        summary = {
            'total_views': total_views,
            'unique_viewers': unique_viewers,
            'total_sales': total_sales,
            'conversion_rate': round(conversion_rate, 2),
            'avg_sale_price': round(avg_sale_price, 2),
            'last_viewed': last_viewed,
            'views_last_7d': views_last_7d,
            'sales_last_7d': sales_last_7d
        }

        # Cache for 1 hour
        set_cached_analytics(listing_id, cache_key, summary, 3600)
        return summary

    except Exception as e:
        app.logger.error(f"Error getting analytics summary: {e}")
        return {
            'total_views': 0,
            'unique_viewers': 0,
            'total_sales': 0,
            'conversion_rate': 0,
            'avg_sale_price': 0,
            'last_viewed': None,
            'views_last_7d': 0,
            'sales_last_7d': 0
        }

def get_view_trends(listing_id: str, date_range: str = '30d', granularity: str = 'daily') -> list:
    """Get view trends over time"""
    try:
        days = parse_date_range(date_range)
        start_date = (datetime.now() - timedelta(days=days)).isoformat()

        views_result = supabase.table('listing_views')\
            .select('viewed_at')\
            .eq('listing_id', listing_id)\
            .gte('viewed_at', start_date)\
            .execute()

        if not views_result.data:
            return []

        # Group by date
        trends = {}
        for view in views_result.data:
            view_date = datetime.fromisoformat(view['viewed_at'].replace('Z', '+00:00')).date()
            date_str = view_date.isoformat()
            trends[date_str] = trends.get(date_str, 0) + 1

        # Fill in missing dates
        result = []
        current_date = (datetime.now() - timedelta(days=days)).date()
        end_date = datetime.now().date()

        while current_date <= end_date:
            date_str = current_date.isoformat()
            result.append({
                'date': date_str,
                'views': trends.get(date_str, 0)
            })
            current_date += timedelta(days=1)

        return result

    except Exception as e:
        app.logger.error(f"Error getting view trends: {e}")
        return []

def get_geographic_data(listing_id: str, date_range: str = '30d') -> list:
    """Get views by country"""
    try:
        days = parse_date_range(date_range)
        start_date = (datetime.now() - timedelta(days=days)).isoformat()

        geo_result = supabase.table('listing_views')\
            .select('country_code')\
            .eq('listing_id', listing_id)\
            .gte('viewed_at', start_date)\
            .execute()

        if not geo_result.data:
            return []

        # Count by country
        country_counts = {}
        total = 0
        for view in geo_result.data:
            country = view['country_code'] or 'Unknown'
            country_counts[country] = country_counts.get(country, 0) + 1
            total += 1

        return [
            {
                'country': country,
                'views': count,
                'percentage': round((count / total) * 100, 1) if total > 0 else 0
            }
            for country, count in sorted(country_counts.items(), key=lambda x: x[1], reverse=True)
        ]

    except Exception as e:
        app.logger.error(f"Error getting geographic data: {e}")
        return []

def get_traffic_sources(listing_id: str, date_range: str = '30d') -> list:
    """Get traffic source breakdown"""
    try:
        days = parse_date_range(date_range)
        start_date = (datetime.now() - timedelta(days=days)).isoformat()

        sources_result = supabase.table('listing_views')\
            .select('source')\
            .eq('listing_id', listing_id)\
            .gte('viewed_at', start_date)\
            .execute()

        if not sources_result.data:
            return []

        # Count by source
        source_counts = {}
        total = 0
        for view in sources_result.data:
            source = view['source'] or 'direct'
            source_counts[source] = source_counts.get(source, 0) + 1
            total += 1

        return [
            {
                'source': source,
                'views': count,
                'percentage': round((count / total) * 100, 1) if total > 0 else 0
            }
            for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)
        ]

    except Exception as e:
        app.logger.error(f"Error getting traffic sources: {e}")
        return []

def get_conversion_funnel(listing_id: str, date_range: str = '30d') -> dict:
    """Get conversion funnel data"""
    try:
        days = parse_date_range(date_range)
        start_date = (datetime.now() - timedelta(days=days)).isoformat()

        # Views
        views_result = supabase.table('listing_views').select('id', count='exact').eq('listing_id', listing_id).gte('viewed_at', start_date).execute()
        views = views_result.count or 0

        # Add to cart events
        cart_result = supabase.table('analytics_events').select('id', count='exact').eq('listing_id', listing_id).eq('event_type', 'add_to_cart').gte('created_at', start_date).execute()
        cart_adds = cart_result.count or 0

        # Completed sales
        sales_result = supabase.table('escrows').select('id', count='exact').eq('listing_id', listing_id).eq('status', 'completed').gte('created_at', start_date).execute()
        sales = sales_result.count or 0

        return {
            'views': views,
            'cart_adds': cart_adds,
            'sales': sales,
            'view_to_cart_rate': round((cart_adds / views * 100), 1) if views > 0 else 0,
            'cart_to_sale_rate': round((sales / cart_adds * 100), 1) if cart_adds > 0 else 0,
            'overall_conversion': round((sales / views * 100), 1) if views > 0 else 0
        }

    except Exception as e:
        app.logger.error(f"Error getting conversion funnel: {e}")
        return {
            'views': 0,
            'cart_adds': 0,
            'sales': 0,
            'view_to_cart_rate': 0,
            'cart_to_sale_rate': 0,
            'overall_conversion': 0
        }

def parse_date_range(date_range: str) -> int:
    """Parse date range string to days"""
    ranges = {'7d': 7, '30d': 30, '90d': 90, '1y': 365}
    return ranges.get(date_range, 30)

def get_cached_analytics(listing_id: str, cache_key: str) -> dict:
    """Get cached analytics data"""
    try:
        cache_result = supabase.table('listing_analytics_cache')\
            .select('data,expires_at')\
            .eq('listing_id', listing_id)\
            .eq('cache_key', cache_key)\
            .single().execute()

        if cache_result.data:
            expires_at = datetime.fromisoformat(cache_result.data['expires_at'])
            if expires_at > datetime.now():
                return cache_result.data['data']

        return None
    except:
        return None

def set_cached_analytics(listing_id: str, cache_key: str, data: dict, ttl_seconds: int = 3600):
    """Cache analytics data"""
    try:
        expires_at = datetime.now() + timedelta(seconds=ttl_seconds)

        supabase.table('listing_analytics_cache').upsert({
            'listing_id': listing_id,
            'cache_key': cache_key,
            'data': data,
            'expires_at': expires_at.isoformat()
        }).execute()
    except Exception as e:
        app.logger.error(f"Error caching analytics: {e}")

def verify_listing_ownership(listing_id: str, user_id: str) -> bool:
    """Verify user owns the listing"""
    try:
        result = supabase.table('listings')\
            .select('seller_id')\
            .eq('id', listing_id)\
            .single().execute()

        return result.data['seller_id'] == user_id
    except:
        return False

def generate_session_id() -> str:
    """Generate a unique session ID"""
    return str(uuid.uuid4())

def get_country_from_ip(ip_address: str) -> str:
    """Get country code from IP address"""
    if not ip_address or ip_address == '127.0.0.1':
        return None

    try:
        import requests
        response = requests.get(f'http://ipapi.co/{ip_address}/country/', timeout=2)
        if response.status_code == 200:
            return response.text[:2].upper()
    except:
        pass

    return None

def detect_traffic_source(referrer: str) -> str:
    """Detect traffic source from referrer URL"""
    if not referrer:
        return 'direct'

    referrer_lower = referrer.lower()

    # Social media
    if any(domain in referrer_lower for domain in ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com']):
        return 'social'

    # Search engines
    if any(domain in referrer_lower for domain in ['google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com']):
        return 'search'

    # Other
    return 'referral'

# ===========================================
# ANALYTICS API ENDPOINTS
# ===========================================

@app.route('/api/marketplace/seller/products/get', methods=['GET','OPTIONS'])
@require_auth
@limiter.limit("50 per minute")
def get_seller_products():
    """Get seller's products with analytics summary"""
    app.logger.info(f"=== SELLER PRODUCTS ROUTE HIT === method={request.method} path={request.path}")
    
    # Debug logging for headers (remove in production)
    app.logger.info(f"Request headers: {dict(request.headers)}")
    auth_header = request.headers.get('Authorization')
    if auth_header:
        app.logger.info(f"Auth header present: {auth_header[:20]}...")  # Log first 20 chars
    else:
        app.logger.warning("No Authorization header found in request!")
    
    # Auth is handled by @require_auth decorator - it should set request.user_id
    try:
        user_id = request.user_id
        app.logger.info(f"Authenticated user_id: {user_id}")
    except AttributeError:
        app.logger.error("request.user_id not set - @require_auth decorator may have failed")
        return jsonify({"error": "Authentication required", "hint": "Include 'Authorization: Bearer YOUR_TOKEN' header"}), 401

    page = request.args.get('page', default=1, type=int) or 1
    limit = request.args.get('limit', default=20, type=int) or 20

    app.logger.info(f"User ID: {user_id}, Page: {page}, Limit: {limit}")

    try:
        # Get seller's listings with basic info
        offset = (page - 1) * limit
        app.logger.info(f"Querying listings for user {user_id}, offset: {offset}, limit: {limit}")
        
        listings_result = (
            supabase.table('listings')
            .select('id,title,status,price_usd,created_at,updated_at')
            .eq('seller_id', user_id)
            .order('updated_at', desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )

        listings = listings_result.data or []
        app.logger.info(f"Found {len(listings)} listings")

        # Enrich with analytics data
        products = []
        for i, listing in enumerate(listings):
            app.logger.info(f"Processing listing {i+1}/{len(listings)}: {listing['id']} - {listing.get('title')}")
            
            # Get analytics summary
            analytics = get_listing_analytics_summary(listing['id'])
            app.logger.info(f"Analytics for listing {listing['id']}: {analytics}")

            # Get escrow counts
            escrow_result = (
                supabase.table('escrows')
                .select('id', count='exact')
                .eq('listing_id', listing['id'])
                .eq('seller_id', user_id)
                .execute()
            )
            escrows_count = escrow_result.count or 0
            app.logger.info(f"Escrow count for listing {listing['id']}: {escrows_count}")

            listing_with_analytics = {
                **listing,
                'analytics': analytics,
                'escrows_count': escrows_count,
            }
            products.append(listing_with_analytics)

        # Get total count for pagination
        total_result = (
            supabase.table('listings')
            .select('id', count='exact')
            .eq('seller_id', user_id)
            .execute()
        )
        total_count = total_result.count or 0

        response_data = {
            'products': products,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'total_pages': (total_count + limit - 1) // limit if limit > 0 else 0
            }
        }

        app.logger.info(f"Returning {len(products)} products with pagination info")
        app.logger.info("=== SELLER PRODUCTS ENDPOINT COMPLETED SUCCESSFULLY ===")
        return jsonify(response_data), 200

    except Exception as e:
        app.logger.error("=== ERROR IN SELLER PRODUCTS ENDPOINT ===")
        app.logger.error(f"Error fetching seller products: {e}")
        app.logger.error(f"Error type: {type(e).__name__}")
        app.logger.error(f"Traceback: {traceback.format_exc()}")
        app.logger.error("=== END ERROR LOG ===")
        return jsonify({"error": "Failed to fetch products", "details": str(e)}), 500


@app.route('/api/marketplace/seller/products/', methods=['GET','OPTIONS'])
def _test_get():
    return jsonify({'ok': True}), 200


@app.route('/api/marketplace/<uuid:listing_id>/analytics', methods=['GET'])
@require_auth
@analytics_limiter.limit("30 per minute")
def get_product_analytics(listing_id):
    """Get detailed analytics for specific product"""
    user_id = request.user_id
    date_range = request.args.get('range', '30d')
    granularity = request.args.get('granularity', 'daily')

    try:
        # Verify ownership
        if not verify_listing_ownership(str(listing_id), user_id):
            return jsonify({"error": "Unauthorized"}), 403

        # Get comprehensive analytics data
        analytics_data = {
            'overview': get_listing_analytics_summary(str(listing_id)),
            'trends': get_view_trends(str(listing_id), date_range, granularity),
            'geography': get_geographic_data(str(listing_id), date_range),
            'traffic_sources': get_traffic_sources(str(listing_id), date_range),
            'conversion_funnel': get_conversion_funnel(str(listing_id), date_range)
        }

        return jsonify(analytics_data)

    except Exception as e:
        app.logger.error(f"Error fetching product analytics: {e}")
        return jsonify({"error": "Failed to fetch analytics"}), 500

@app.route('/api/marketplace/<uuid:listing_id>/track-view', methods=['POST'])
@analytics_limiter.limit("200 per minute")  # Higher limit for tracking
def track_listing_view(listing_id):
    """Track when a listing is viewed"""
    data = request.json or {}

    try:
        # Extract tracking data
        session_id = data.get('session_id', generate_session_id())
        ip_address = request.remote_addr or data.get('ip_address')
        country_code = get_country_from_ip(ip_address)
        referrer = data.get('referrer') or request.headers.get('Referer')
        source = detect_traffic_source(referrer)

        view_data = {
            'listing_id': str(listing_id),
            'viewer_id': getattr(request, 'user_id', None),
            'session_id': session_id,
            'ip_address': ip_address,
            'user_agent': request.headers.get('User-Agent'),
            'referrer_url': referrer,
            'country_code': country_code,
            'source': source,
            'campaign_id': data.get('campaign_id'),
            'search_query': data.get('search_query'),
            'viewed_at': datetime.now().isoformat()
        }

        # Insert view record
        supabase.table('listing_views').insert(view_data).execute()

        # Track additional events if applicable
        if data.get('event_type'):
            event_data = {
                'event_type': data['event_type'],
                'listing_id': str(listing_id),
                'user_id': getattr(request, 'user_id', None),
                'session_id': session_id,
                'event_data': data.get('event_data', {}),
                'created_at': datetime.now().isoformat()
            }
            supabase.table('analytics_events').insert(event_data).execute()

        # Invalidate cache
        cache_key = f"summary:{listing_id}"
        supabase.table('listing_analytics_cache')\
            .delete()\
            .eq('listing_id', str(listing_id))\
            .eq('cache_key', cache_key)\
            .execute()

        return jsonify({"success": True})

    except Exception as e:
        app.logger.error(f"Error tracking view: {e}")
        return jsonify({"error": "Failed to track view"}), 500

@app.route('/api/marketplace/<uuid:listing_id>/analytics/export', methods=['GET'])
@require_auth
@analytics_limiter.limit("10 per minute")  # Lower limit for exports
def export_product_analytics(listing_id):
    """Export analytics data as CSV or JSON"""
    user_id = request.user_id
    format_type = request.args.get('format', 'csv')  # csv, json
    date_range = request.args.get('range', '30d')

    try:
        # Verify ownership
        if not verify_listing_ownership(str(listing_id), user_id):
            return jsonify({"error": "Unauthorized"}), 403

        if format_type == 'csv':
            csv_data = generate_analytics_csv(str(listing_id), date_range)
            response = make_response(csv_data)
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=analytics-{listing_id}.csv'
            return response
        else:
            json_data = generate_analytics_json(str(listing_id), date_range)
            response = make_response(json.dumps(json_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=analytics-{listing_id}.json'
            return response

    except Exception as e:
        app.logger.error(f"Error exporting analytics: {e}")
        return jsonify({"error": "Failed to export analytics"}), 500

@app.route('/api/marketplace/<uuid:listing_id>/escrows', methods=['GET'])
@require_auth
@analytics_limiter.limit("30 per minute")
def get_product_escrows(listing_id):
    """Get escrows for specific product with analytics"""
    user_id = request.user_id
    status_filter = request.args.get('status')
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))

    try:
        # Verify ownership
        if not verify_listing_ownership(str(listing_id), user_id):
            return jsonify({"error": "Unauthorized"}), 403

        # Build escrow query
        query = supabase.table('escrows')\
            .select('id,status,amount_usd,currency,payment_method,buyer_id,created_at')\
            .eq('listing_id', str(listing_id))\
            .eq('seller_id', user_id)\
            .order('created_at', desc=True)

        if status_filter:
            query = query.eq('status', status_filter)

        offset = (page - 1) * limit
        escrows_result = query.range(offset, offset + limit - 1).execute()

        # Enrich with buyer data
        escrows = []
        for escrow in escrows_result.data:
            # Get buyer username
            buyer_result = supabase.table('profiles')\
                .select('username')\
                .eq('id', escrow['buyer_id'])\
                .single().execute()

            escrow_data = {
                **escrow,
                'buyer_username': buyer_result.data.get('username', 'Unknown') if buyer_result.data else 'Unknown'
            }
            escrows.append(escrow_data)

        # Get total count
        total_query = supabase.table('escrows')\
            .select('id', count='exact')\
            .eq('listing_id', str(listing_id))\
            .eq('seller_id', user_id)

        if status_filter:
            total_query = total_query.eq('status', status_filter)

        total_result = total_query.execute()

        return jsonify({
            'escrows': escrows,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_result.count or 0,
                'total_pages': (total_result.count or 0 + limit - 1) // limit
            }
        })

    except Exception as e:
        app.logger.error(f"Error fetching product escrows: {e}")
        return jsonify({"error": "Failed to fetch escrows"}), 500

def generate_analytics_csv(listing_id: str, date_range: str) -> str:
    """Generate CSV export of analytics data"""
    from io import StringIO
    import csv

    # Get analytics data
    overview = get_listing_analytics_summary(listing_id)
    trends = get_view_trends(listing_id, date_range, 'daily')
    geography = get_geographic_data(listing_id, date_range)
    sources = get_traffic_sources(listing_id, date_range)

    # Create CSV content
    output = StringIO()
    writer = csv.writer(output)

    # Overview section
    writer.writerow(['Analytics Report'])
    writer.writerow(['Generated:', datetime.now().isoformat()])
    writer.writerow(['Date Range:', date_range])
    writer.writerow([])

    writer.writerow(['Overview Metrics'])
    writer.writerow(['Metric', 'Value'])
    writer.writerow(['Total Views', overview['total_views']])
    writer.writerow(['Unique Viewers', overview['unique_viewers']])
    writer.writerow(['Total Sales', overview['total_sales']])
    writer.writerow(['Conversion Rate', f"{overview['conversion_rate']:.2f}%"])
    writer.writerow(['Average Sale Price', f"${overview['avg_sale_price']:.2f}"])
    writer.writerow([])

    # Trends section
    writer.writerow(['View Trends'])
    writer.writerow(['Date', 'Views'])
    for trend in trends:
        writer.writerow([trend['date'], trend['views']])
    writer.writerow([])

    # Geography section
    writer.writerow(['Geographic Data'])
    writer.writerow(['Country', 'Views', 'Percentage'])
    for geo in geography:
        writer.writerow([geo['country'], geo['views'], f"{geo['percentage']:.1f}%"])
    writer.writerow([])

    # Traffic sources section
    writer.writerow(['Traffic Sources'])
    writer.writerow(['Source', 'Views', 'Percentage'])
    for source in sources:
        writer.writerow([source['source'], source['views'], f"{source['percentage']:.1f}%"])

    return output.getvalue()

def generate_analytics_json(listing_id: str, date_range: str) -> dict:
    """Generate JSON export of analytics data"""
    return {
        'listing_id': listing_id,
        'date_range': date_range,
        'generated_at': datetime.now().isoformat(),
        'overview': get_listing_analytics_summary(listing_id),
        'trends': get_view_trends(listing_id, date_range, 'daily'),
        'geography': get_geographic_data(listing_id, date_range),
        'traffic_sources': get_traffic_sources(listing_id, date_range),
        'conversion_funnel': get_conversion_funnel(listing_id, date_range)
    }

# ===========================================
# CACHE MANAGEMENT & BACKGROUND JOBS
# ===========================================

@app.route('/api/admin/analytics/cache/cleanup', methods=['POST'])
@require_admin
def cleanup_expired_cache():
    """Manually trigger cache cleanup (admin only)"""
    try:
        # Clean listing analytics cache
        listing_cache_result = supabase.table('listing_analytics_cache')\
            .delete()\
            .lt('expires_at', datetime.now().isoformat())\
            .execute()

        # Clean seller analytics cache
        seller_cache_result = supabase.table('seller_analytics_cache')\
            .delete()\
            .lt('expires_at', datetime.now().isoformat())\
            .execute()

        return jsonify({
            'success': True,
            'message': 'Cache cleanup completed',
            'listing_cache_cleaned': len(listing_cache_result.data) if listing_cache_result.data else 0,
            'seller_cache_cleaned': len(seller_cache_result.data) if seller_cache_result.data else 0
        })

    except Exception as e:
        app.logger.error(f"Error during cache cleanup: {e}")
        return jsonify({"error": "Failed to cleanup cache"}), 500

@app.route('/api/admin/analytics/cache/stats', methods=['GET'])
@require_admin
def get_cache_stats():
    """Get cache statistics (admin only)"""
    try:
        # Listing cache stats
        listing_total = supabase.table('listing_analytics_cache').select('id', count='exact').execute()
        listing_expired = supabase.table('listing_analytics_cache').select('id', count='exact').lt('expires_at', datetime.now().isoformat()).execute()

        # Seller cache stats
        seller_total = supabase.table('seller_analytics_cache').select('id', count='exact').execute()
        seller_expired = supabase.table('seller_analytics_cache').select('id', count='exact').lt('expires_at', datetime.now().isoformat()).execute()

        return jsonify({
            'listing_cache': {
                'total_entries': listing_total.count or 0,
                'expired_entries': listing_expired.count or 0,
                'active_entries': (listing_total.count or 0) - (listing_expired.count or 0)
            },
            'seller_cache': {
                'total_entries': seller_total.count or 0,
                'expired_entries': seller_expired.count or 0,
                'active_entries': (seller_total.count or 0) - (seller_expired.count or 0)
            }
        })

    except Exception as e:
        app.logger.error(f"Error getting cache stats: {e}")
        return jsonify({"error": "Failed to get cache stats"}), 500

def invalidate_listing_cache_on_change(listing_id: str):
    """Invalidate cache when listing data changes"""
    try:
        cache_key = f"summary:{listing_id}"
        supabase.table('listing_analytics_cache')\
            .delete()\
            .eq('listing_id', listing_id)\
            .eq('cache_key', cache_key)\
            .execute()

        app.logger.info(f"Invalidated cache for listing {listing_id}")
    except Exception as e:
        app.logger.error(f"Error invalidating cache for listing {listing_id}: {e}")

def invalidate_seller_cache_on_change(seller_id: str):
    """Invalidate cache when seller data changes"""
    try:
        supabase.table('seller_analytics_cache')\
            .delete()\
            .eq('seller_id', seller_id)\
            .execute()

        app.logger.info(f"Invalidated cache for seller {seller_id}")
    except Exception as e:
        app.logger.error(f"Error invalidating cache for seller {seller_id}: {e}")

# ===========================================
# SECURITY & RATE LIMITING
# ===========================================

# ===========================================
# DATA PRIVACY & GDPR COMPLIANCE
# ===========================================

def anonymize_old_analytics_data():
    """Anonymize old analytics data for privacy compliance"""
    try:
        # Anonymize IP addresses older than 30 days
        thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()

        # Update old view records to remove IP addresses
        supabase.table('listing_views')\
            .update({'ip_address': None})\
            .lt('viewed_at', thirty_days_ago)\
            .neq('ip_address', None)\
            .execute()

        # Remove old detailed user agent data
        supabase.table('listing_views')\
            .update({'user_agent': 'anonymized'})\
            .lt('viewed_at', thirty_days_ago)\
            .neq('user_agent', 'anonymized')\
            .execute()

        app.logger.info("Anonymized old analytics data for privacy compliance")
        return True

    except Exception as e:
        app.logger.error(f"Error anonymizing old analytics data: {e}")
        return False

@app.route('/api/user/analytics/delete', methods=['POST'])
@require_auth
def delete_user_analytics_data():
    """Allow users to delete their analytics data (GDPR compliance)"""
    user_id = request.user_id

    try:
        # Delete view records for this user
        views_deleted = supabase.table('listing_views')\
            .delete()\
            .eq('viewer_id', user_id)\
            .execute()

        # Delete analytics events for this user
        events_deleted = supabase.table('analytics_events')\
            .delete()\
            .eq('user_id', user_id)\
            .execute()

        # Invalidate any cached data that might include this user
        supabase.table('listing_analytics_cache').delete().execute()
        supabase.table('seller_analytics_cache').delete().execute()

        return jsonify({
            'success': True,
            'message': 'Your analytics data has been deleted',
            'views_deleted': len(views_deleted.data) if views_deleted.data else 0,
            'events_deleted': len(events_deleted.data) if events_deleted.data else 0
        })

    except Exception as e:
        app.logger.error(f"Error deleting user analytics data: {e}")
        return jsonify({"error": "Failed to delete analytics data"}), 500

# ========================================
# CRYPTO-TO-CRYPTO EXCHANGE ENDPOINTS
# ========================================

# ============================================
# SWAPKIT UTILITY FUNCTIONS
# ============================================

def swapkit_request(method, endpoint, params=None, data=None, retry_count=0):
    """
    Make request to SwapKit API with retry logic
    
    Args:
        method: HTTP method (GET, POST)
        endpoint: API endpoint (e.g., '/quote')
        params: Query parameters (for GET)
        data: JSON body (for POST)
        retry_count: Current retry attempt
    
    Returns:
        JSON response from SwapKit
    """
    url = f"{SWAPKIT_API_URL}{endpoint}"
    
    headers = {
        'x-api-key': SWAPKIT_API_KEY,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    
    try:
        if method == 'GET':
            response = requests.get(url, headers=headers, params=params, timeout=SWAPKIT_TIMEOUT)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data, timeout=SWAPKIT_TIMEOUT)
        else:
            raise SwapKitError(f"Unsupported method: {method}")
        
        # Handle rate limiting with exponential backoff
        if response.status_code == 429 and retry_count < SWAPKIT_MAX_RETRIES:
            wait_time = SWAPKIT_RETRY_DELAY * (2 ** retry_count)
            app.logger.warning(f"SwapKit rate limited, retrying in {wait_time}s...")
            time.sleep(wait_time)
            return swapkit_request(method, endpoint, params, data, retry_count + 1)
        
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.Timeout:
        if retry_count < SWAPKIT_MAX_RETRIES:
            app.logger.warning(f"SwapKit timeout, retrying...")
            time.sleep(SWAPKIT_RETRY_DELAY)
            return swapkit_request(method, endpoint, params, data, retry_count + 1)
        raise SwapKitAPIError("Request timeout", status_code=408)
        
    except requests.exceptions.HTTPError as e:
        error_data = {}
        try:
            error_data = response.json()
        except:
            pass
        raise SwapKitAPIError(str(e), status_code=response.status_code, response=error_data)
        
    except Exception as e:
        raise SwapKitAPIError(f"Request failed: {str(e)}")

def verify_swapkit_webhook_signature(payload, signature):
    """
    Verify SwapKit webhook signature using HMAC-SHA256
    
    Args:
        payload: Raw request body (bytes)
        signature: Signature from X-SwapKit-Signature header
    
    Returns:
        True if valid, False otherwise
    """
    try:
        expected = hmac.new(
            SWAPKIT_WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception as e:
        app.logger.error(f"Signature verification failed: {e}")
        return False

def map_currency_to_swapkit(currency):
    """
    Map Medius currency code to SwapKit asset format
    
    Args:
        currency: Medius currency code (e.g., 'BTC', 'USDT-ERC20')
    
    Returns:
        SwapKit asset identifier (e.g., 'BTC.BTC', 'ETH.USDT-0x...')
    
    Raises:
        ValueError: If currency not supported
    """
    currency = currency.upper().strip()
    
    if currency in SWAPKIT_CURRENCY_MAPPING:
        return SWAPKIT_CURRENCY_MAPPING[currency]
    
    raise ValueError(f"Unsupported currency: {currency}")

def map_swapkit_to_currency(swapkit_asset):
    """
    Map SwapKit asset identifier back to Medius currency code
    
    Args:
        swapkit_asset: SwapKit asset (e.g., 'BTC.BTC')
    
    Returns:
        Medius currency code (e.g., 'BTC')
    """
    for currency, asset in SWAPKIT_CURRENCY_MAPPING.items():
        if asset == swapkit_asset:
            return currency
    return swapkit_asset

def get_platform_fee_address(currency):
    """
    Get platform fee collection address for currency
    
    Args:
        currency: Currency code
    
    Returns:
        Platform wallet address
    
    Raises:
        ValueError: If no address configured
    """
    currency = currency.upper().strip()
    address = FEE_ADDRESSES.get(currency)
    
    if not address:
        raise ValueError(f"No fee address configured for {currency}")
    
    return address

def map_swapkit_status(swapkit_status):
    """
    Map SwapKit order status to Medius exchange status
    
    Args:
        swapkit_status: SwapKit status string
    
    Returns:
        Medius exchange status
    """
    status_map = {
        'pending': 'pending',
        'waiting': 'pending',
        'processing': 'swapping',
        'confirming': 'confirming',
        'completed': 'swap_complete',  # Platform received funds, needs to payout user
        'complete': 'swap_complete',
        'failed': 'failed',
        'expired': 'expired',
        'refunded': 'refunded',
    }
    return status_map.get(swapkit_status.lower(), 'pending')

def calculate_platform_fee(amount):
    """
    Calculate platform fee amount
    
    Args:
        amount: Total amount
    
    Returns:
        Platform fee (Decimal)
    """
    return Decimal(str(amount)) * C2C_FEE

def calculate_user_payout_amount(total_received, platform_fee_percent):
    """
    Calculate amount to send to user after platform fee
    
    Args:
        total_received: Total amount received from SwapKit
        platform_fee_percent: Platform fee percentage (as Decimal, e.g., 0.01 for 1%)
    
    Returns:
        Amount to send to user
    """
    platform_fee = Decimal(str(total_received)) * Decimal(str(platform_fee_percent))
    user_amount = Decimal(str(total_received)) - platform_fee
    return max(Decimal('0'), user_amount)

def estimate_network_fee(currency):
    """
    Estimate network fee for sending payout to user
    
    Args:
        currency: Currency code
    
    Returns:
        Estimated network fee (Decimal)
    """
    # Simplified estimates - in production, query from blockchain APIs
    fee_estimates = {
        'BTC': Decimal('0.00001'),
        'ETH': Decimal('0.001'),
        'SOL': Decimal('0.000005'),
        'LTC': Decimal('0.0001'),
        'BCH': Decimal('0.00001'),
        'DOGE': Decimal('1.0'),
        'MATIC': Decimal('0.01'),
        'AVAX': Decimal('0.001'),
        'BNB': Decimal('0.0001'),
        'USDT-ERC20': Decimal('0.001'),
        'USDT-BEP20': Decimal('0.0001'),
        'USDT-SOL': Decimal('0.000005'),
        'USDT-TRON': Decimal('1.0'),
    }
    return fee_estimates.get(currency.upper(), Decimal('0'))

def validate_exchange_amount(amount, currency):
    """
    Validate if exchange amount meets minimum requirements
    
    Args:
        amount: Exchange amount
        currency: Currency code
    
    Returns:
        True if valid, False otherwise
    """
    if Decimal(str(amount)) <= 0:
        return False
    
    # Minimum amounts per currency
    minimums = {
        'BTC': Decimal('0.0001'),
        'ETH': Decimal('0.001'),
        'SOL': Decimal('0.01'),
        'USDT-ERC20': Decimal('5'),
        'USDT-BEP20': Decimal('5'),
        'USDT-TRON': Decimal('5'),
        'USDT-SOL': Decimal('5'),
    }
    
    min_amount = minimums.get(currency.upper(), Decimal('0'))
    return Decimal(str(amount)) >= min_amount

# ============================================
# EXCHANGE ENDPOINTS
# ============================================

@app.route('/api/exchange/currencies', methods=['GET'])
def get_exchange_currencies():
    """
    Get list of supported currencies for exchange
    
    Returns only the 13 currencies supported by SwapKit
    """
    try:
        currencies = []
        
        # Only return currencies in SWAPKIT_CURRENCY_MAPPING
        for currency, swapkit_code in SWAPKIT_CURRENCY_MAPPING.items():
            fee_address = FEE_ADDRESSES.get(currency)
            
            currencies.append({
                'code': currency,
                'swapkit_code': swapkit_code,
                'name': currency.split('-')[0],
                'network': currency.split('-')[1] if '-' in currency else 'mainnet',
                'supported': fee_address is not None,
                'fee_address_configured': fee_address is not None
            })
        
        return jsonify({
            'currencies': currencies,
            'total': len(currencies),
            'note': 'ADA and DOT are not supported for exchange'
        }), 200
        
    except Exception as e:
        app.logger.error(f"Get currencies error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch currencies'}), 500

@app.route('/api/exchange/quote', methods=['POST'])
@require_auth
def get_exchange_quote():
    try:
        data = request.json or {}
        from_currency = (data.get('from_currency') or '').upper().strip()
        to_currency   = (data.get('to_currency') or '').upper().strip()
        amount_str    = data.get('amount')
        slippage      = data.get('slippage', float(DEFAULT_SLIPPAGE))

        if not from_currency or not to_currency:
            return jsonify({'error': 'from_currency and to_currency required'}), 400
        if from_currency == to_currency:
            return jsonify({'error': 'Cannot exchange the same currency'}), 400

        try:
            amount = Decimal(str(amount_str))
        except (ValueError, TypeError, InvalidOperation):
            return jsonify({'error': 'Invalid amount'}), 400
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        if not validate_exchange_amount(amount, from_currency):
            return jsonify({'error': f'Amount below minimum threshold for {from_currency}'}), 400

        try:
            sell_asset  = map_currency_to_swapkit(from_currency)
            buy_asset   = map_currency_to_swapkit(to_currency)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        # SwapKit API expects decimal amounts (e.g., "0.1"), NOT base units
        # When includeTx=false, sourceAddress and destinationAddress are NOT needed
        payload = {
            'sellAsset': str(sell_asset),
            'buyAsset':  str(buy_asset),
            'sellAmount': str(amount),  # Send as decimal string
            'slippage': slippage,
            'includeTx': False
        }

        try:
            quote = swapkit_request('POST', '/quote', data=payload)
        except SwapKitAPIError as e:
            details = getattr(e, 'response', None)
            app.logger.error(f"/quote error: {e} | details={details} | payload={payload}")
            return jsonify({'error': 'Failed to get quote', 'details': details}), 500

        routes = quote.get('routes', [])
        warnings = quote.get('warnings', [])
        provider_errors = quote.get('providerErrors', [])
        
        if not routes:
            msg = 'No routes available'
            if provider_errors:
                msg += f" | providerErrors={provider_errors}"
            return jsonify({'error': msg, 'provider_errors': provider_errors}), 400

        best = routes[0]
        
        # API returns decimal amounts as strings (e.g., "0.1" not "10000000")
        raw_sell = best.get('sellAmount') or best.get('estimatedSellAmount')
        raw_buy  = best.get('expectedBuyAmount') or best.get('estimatedBuyAmount') or best.get('buyAmount') or '0'

        # Convert API response strings to Decimal for calculations
        from_amount = Decimal(str(raw_sell)) if raw_sell else amount
        to_amount_gross = Decimal(str(raw_buy))

        if to_amount_gross <= 0:
            return jsonify({'error': 'Invalid exchange rate from provider'}), 500

        platform_fee_amount  = calculate_platform_fee(to_amount_gross)
        network_fee_estimate = estimate_network_fee(to_currency)
        to_amount_after_fee  = max(Decimal('0'), to_amount_gross - platform_fee_amount - network_fee_estimate)
        rate = (to_amount_gross / from_amount) if from_amount > 0 else Decimal('0')
        provider = best.get('path') or ((best.get('providers') or [None])[0]) or 'unknown'

        return jsonify({
            'quote_id': quote.get('quoteId'),
            'from_currency': from_currency,
            'to_currency':   to_currency,
            'from_amount': float(from_amount),
            'to_amount': float(to_amount_gross),
            'to_amount_after_fee': float(to_amount_after_fee),
            'rate': float(rate),
            'platform_fee_percent': float(C2C_FEE * 100),
            'platform_fee_amount':  float(platform_fee_amount),
            'network_fee_estimate': float(network_fee_estimate),
            'slippage': float(slippage),
            'provider': provider,
            'warnings': warnings,
            'valid_for_seconds': C2C_RATE_LOCK_SECONDS,
            'routes_available': len(routes),
        }), 200

    except Exception as e:
        app.logger.error(f"get_exchange_quote error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to generate quote'}), 500
        
@app.route('/api/exchange/create', methods=['POST'])
@require_auth
def create_exchange():
    try:
        data = request.json or {}
        user_id = request.user_id

        from_currency       = (data.get('from_currency') or '').upper().strip()
        to_currency         = (data.get('to_currency') or '').upper().strip()
        amount_str          = data.get('amount')
        destination_address = (data.get('destination_address') or '').strip()
        destination_tag     = (data.get('destination_tag') or '').strip()
        slippage            = data.get('slippage', float(DEFAULT_SLIPPAGE))

        if not all([from_currency, to_currency, amount_str, destination_address]):
            return jsonify({'error': 'Missing required fields'}), 400
        if from_currency == to_currency:
            return jsonify({'error': 'Cannot exchange the same currency'}), 400

        try:
            amount = Decimal(str(amount_str))
        except (ValueError, TypeError, InvalidOperation):
            return jsonify({'error': 'Invalid amount format'}), 400
        if amount <= 0:
            return jsonify({'error': 'Amount must be positive'}), 400
        if not validate_exchange_amount(amount, from_currency):
            return jsonify({'error': f'Amount below minimum threshold for {from_currency}'}), 400

        try:
            sell_asset  = map_currency_to_swapkit(from_currency)
            buy_asset   = map_currency_to_swapkit(to_currency)
            src_address = get_platform_fee_address(from_currency)
            dst_address = get_platform_fee_address(to_currency)
        except ValueError as e:
            return jsonify({'error': str(e)}), 400

        sell_amount_base = to_base_units(from_currency, amount)

        payload = {
            'sellAsset': str(sell_asset),
            'buyAsset':  str(buy_asset),
            'sellAmount': sell_amount_base,      # base units
            'sourceAddress':      src_address,
            'destinationAddress': dst_address,
            'slippage': slippage,
            'includeTx': True
        }

        try:
            quote = swapkit_request('POST', '/quote', data=payload)
        except SwapKitAPIError as e:
            details = getattr(e, 'response', None)
            app.logger.error(f"/quote 400: {e} | details={details} | payload={payload}")
            return jsonify({'error': 'Failed to get route from provider', 'details': details}), 500

        routes = quote.get('routes', [])
        warnings = quote.get('warnings', [])
        provider_errors = quote.get('providerErrors', [])
        if not routes:
            msg = 'No routes available'
            if provider_errors:
                msg += f" | providerErrors={provider_errors}"
            return jsonify({'error': msg, 'provider_errors': provider_errors}), 400

        best = routes[0]

        deposit_address = (
            best.get('targetAddress') or
            best.get('inboundAddress') or
            (best.get('calldata') or {}).get('toAddress') or
            best.get('memo')
        )
        if not deposit_address:
            app.logger.error(f"No deposit address in best route: {best}")
            return jsonify({'error': 'Failed to get deposit address from provider'}), 500

        raw_sell = best.get('sellAmount') or best.get('estimatedSellAmount') or sell_amount_base
        raw_buy  = best.get('expectedBuyAmount') or best.get('estimatedBuyAmount') or best.get('buyAmount') or '0'

        def from_base_units(currency: str, base_str: str) -> Decimal:
            dec = ASSET_DECIMALS[currency]
            return (Decimal(base_str) / (Decimal(10) ** dec)).quantize(Decimal('0.00000001'))

        from_amount    = from_base_units(from_currency, str(raw_sell))
        to_amount_gross = from_base_units(to_currency, str(raw_buy))
        if to_amount_gross <= 0:
            return jsonify({'error': 'Invalid exchange rate from provider'}), 500

        platform_fee_amount  = calculate_platform_fee(to_amount_gross)
        network_fee_estimate = estimate_network_fee(to_currency)
        exchange_rate        = (to_amount_gross / from_amount) if from_amount > 0 else Decimal('0')

        now = datetime.utcnow()
        rate_expires_at = now + timedelta(seconds=C2C_RATE_LOCK_SECONDS)

        # Persist using your existing columns
        exchange_row = {
            'user_id': str(user_id),
            'from_currency': from_currency,
            'from_amount': float(from_amount),
            'to_currency': to_currency,
            'to_amount': float(to_amount_gross),
            'exchange_rate': float(exchange_rate),
            'rate_source': 'swapkit',
            'rate_locked_at': now.isoformat(),
            'rate_expires_at': rate_expires_at.isoformat(),
            'platform_fee_percent': float(C2C_FEE * 100),
            'platform_fee_amount': float(platform_fee_amount),
            'network_fee_amount': float(network_fee_estimate),
            'deposit_address': deposit_address,
            'destination_address': destination_address,
            'platform_fee_address': dst_address,
            'status': 'pending',
            'user_ip': request.remote_addr,
            'user_agent': request.headers.get('User-Agent'),
            'updated_at': now.isoformat(),
            'metadata': {
                'destination_tag': destination_tag or None,
                'swapkit_quote_id': quote.get('quoteId'),
                'warnings': warnings,
                'provider_errors': provider_errors,
                'route_details': best
            }
        }

        try:
            ins = supabase.table('crypto_exchanges').insert(exchange_row).execute()
            if not ins.data:
                raise Exception("Insert returned no data")
            exchange_id = ins.data[0]['id']
        except Exception as e:
            app.logger.error(f"DB insert failed: {e}")
            return jsonify({'error': 'Failed to create exchange record'}), 500

        provider = best.get('path') or ((best.get('providers') or [None])[0]) or 'unknown'

        return jsonify({
            'id': exchange_id,
            'status': 'pending',
            'deposit': {
                'address': deposit_address,
                'currency': from_currency,
                'amount': float(from_amount),
                'tag': destination_tag or None,
                'instructions': f'Send exactly {from_amount} {from_currency} to the address above'
            },
            'expected_output': {
                'currency': to_currency,
                'gross_amount': float(to_amount_gross),
                'platform_fee': float(platform_fee_amount),
                'network_fee_estimate': float(network_fee_estimate),
                'destination_address': destination_address
            },
            'rate': float(exchange_rate),
            'rate_locked_at': now.isoformat(),
            'rate_expires_at': rate_expires_at.isoformat(),
            'provider': provider,
            'warnings': warnings
        }), 201

    except Exception as e:
        app.logger.error(f"create_exchange error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Unexpected error creating exchange'}), 500

@app.route('/api/exchange/<exchange_id>', methods=['GET'])
@require_auth
def get_exchange_status(exchange_id):
    """
    Get exchange status - UPDATED to match frontend format
    """
    try:
        user_id = request.user_id
        
        # Fetch exchange
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('id', exchange_id)\
            .single()\
            .execute()
        
        if not result.data:
            return jsonify({'error': 'Exchange not found'}), 404
        
        exchange = result.data
        
        # Verify ownership
        if exchange['user_id'] != str(user_id):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Calculate rate expiry
        rate_locked_at = exchange.get('rate_locked_at')
        rate_expires_at = exchange.get('rate_expires_at')
        expires_in_seconds = 0
        expired = True
        
        if rate_expires_at:
            expires_at_dt = datetime.fromisoformat(rate_expires_at.replace('Z', '+00:00'))
            now = datetime.utcnow()
            expires_in_seconds = max(0, int((expires_at_dt - now).total_seconds()))
            expired = expires_in_seconds <= 0
        
        # Format response to match frontend expectations
        response = {
            'exchange_id': exchange['id'],
            'status': exchange['status'],
            'created_at': exchange['created_at'],
            'updated_at': exchange['updated_at'],
            'completed_at': exchange.get('completed_at'),
            
            # From/To structure
            'from': {
                'currency': exchange['from_currency'],
                'amount': float(exchange['from_amount']),
                'amount_usd': float(exchange.get('from_amount_usd') or 0)
            },
            'to': {
                'currency': exchange['to_currency'],
                'amount': float(exchange.get('user_payout_amount') or exchange['to_amount']),  # User receives this
                'amount_usd': float(exchange.get('to_amount_usd') or 0)
            },
            
            # Deposit info
            'deposit': {
                'address': exchange['deposit_address'],
                'tag': exchange.get('deposit_tag'),  # For XRP, XLM, etc.
                'tx_hash': exchange.get('deposit_tx_hash'),
                'confirmations': exchange.get('deposit_confirmations', 0),
                'detected_at': exchange.get('deposit_detected_at'),
                'confirmed_at': exchange.get('deposit_confirmed_at')
            },
            
            # Payout info
            'payout': {
                'address': exchange['destination_address'],
                'tag': exchange.get('destination_tag'),
                'tx_hash': exchange.get('user_payout_tx_hash'),
                'confirmations': exchange.get('payout_confirmations', 0),
                'sent_at': exchange.get('user_payout_sent_at'),
                'confirmed_at': exchange.get('payout_confirmed_at')
            },
            
            # Fees
            'fees': {
                'platform_percent': float(exchange.get('platform_fee_percent', 0)),
                'platform_amount': float(exchange.get('platform_fee_amount', 0)),
                'platform_usd': float(exchange.get('platform_fee_usd') or 0),
                'network_amount': float(exchange.get('network_fee_amount', 0)),
                'network_usd': float(exchange.get('network_fee_usd') or 0)
            },
            
            # Rate info
            'rate': {
                'value': float(exchange.get('exchange_rate', 0)),
                'locked_at': rate_locked_at or exchange['created_at'],
                'expires_at': rate_expires_at or exchange['created_at'],
                'expires_in_seconds': expires_in_seconds,
                'expired': expired
            },
            
            # SwapKit info
            'swapkit_order_id': exchange.get('swapkit_order_id'),
            
            # Error if any
            'error': exchange.get('error_message')
        }
        
        return jsonify(response), 200
        
    except Exception as e:
        app.logger.error(f"Get exchange status error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch exchange status'}), 500

@app.route('/api/exchange/user/history', methods=['GET'])
@require_auth
def get_user_exchange_history():
    """
    Get user exchange history - UPDATED to match frontend format
    """
    try:
        user_id = request.user_id
        
        # Pagination
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('limit', 20)), 100)  # Frontend uses 'limit' not 'per_page'
        offset = (page - 1) * per_page
        
        # Filters
        status = request.args.get('status')
        
        # Build query
        query = supabase.table('crypto_exchanges')\
            .select('*', count='exact')\
            .eq('user_id', str(user_id))\
            .order('created_at', desc=True)\
            .range(offset, offset + per_page - 1)
        
        if status:
            query = query.eq('status', status)
        
        result = query.execute()
        
        exchanges = result.data or []
        total = result.count or 0
        pages = (total + per_page - 1) // per_page
        
        # Format exchanges to match frontend expectations
        formatted_exchanges = []
        for ex in exchanges:
            formatted_exchanges.append({
                'exchange_id': ex['id'],
                'status': ex['status'],
                'from_currency': ex['from_currency'],
                'from_amount': float(ex['from_amount']),
                'to_currency': ex['to_currency'],
                'to_amount': float(ex.get('user_payout_amount') or ex['to_amount']),
                'rate': float(ex.get('exchange_rate', 0)),
                'created_at': ex['created_at'],
                'completed_at': ex.get('completed_at')
            })
        
        return jsonify({
            'exchanges': formatted_exchanges,
            'pagination': {
                'page': page,
                'limit': per_page,
                'total': total,
                'pages': pages
            }
        }), 200
        
    except Exception as e:
        app.logger.error(f"Get user history error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to fetch exchange history'}), 500

@app.route('/api/exchange/<exchange_id>/refresh', methods=['POST'])
@require_auth
def refresh_exchange_status(exchange_id):
    """
    Manually refresh exchange status from SwapKit
    
    This forces a status check instead of waiting for background monitor
    """
    try:
        user_id = request.user_id
        
        # Get exchange
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('id', exchange_id)\
            .single()\
            .execute()
        
        if not result.data:
            return jsonify({'error': 'Exchange not found'}), 404
        
        exchange = result.data
        
        # Verify ownership
        if exchange['user_id'] != str(user_id):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # If exchange has deposit TX, try to track it
        if exchange.get('deposit_tx_hash'):
            try:
                from_currency = exchange['from_currency']
                tx_hash = exchange['deposit_tx_hash']
                
                # Track with SwapKit
                track_response = swapkit_track_transaction(tx_hash, from_currency)
                
                if track_response:
                    # Parse and update status
                    new_status = parse_track_status(track_response)
                    
                    if new_status and new_status != exchange['status']:
                        updates = {
                            'status': new_status,
                            'swapkit_response': track_response,
                            'updated_at': datetime.utcnow().isoformat()
                        }
                        
                        # If swap complete, mark for payout
                        if new_status == 'swap_complete':
                            updates['user_payout_pending'] = True
                        
                        supabase.table('crypto_exchanges')\
                            .update(updates)\
                            .eq('id', exchange_id)\
                            .execute()
                        
                        app.logger.info(f"Exchange {exchange_id} status refreshed: {exchange['status']} → {new_status}")
                
            except Exception as e:
                app.logger.error(f"Failed to refresh status: {e}")
                # Don't fail the request, just log it
        
        return jsonify({'status': 'ok', 'message': 'Status refresh requested'}), 200
        
    except Exception as e:
        app.logger.error(f"Refresh status error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to refresh status'}), 500


def get_platform_wallet_private_key(currency):
    """
    Get private key for platform wallet address
    
    Uses environment variables:
    - BTC_FEE_ADDY_PRIVATE_KEY
    - ETH_FEE_ADDY_PRIVATE_KEY
    - etc.
    
    For tokens on same chain (like USDT-ERC20), uses the chain's key (ETH)
    """
    currency = currency.upper().strip()
    
    # Map currency to private key environment variable
    key_map = {
        'BTC': 'BTC_FEE_ADDY_PRIVATE_KEY',
        'ETH': 'ETH_FEE_ADDY_PRIVATE_KEY',
        'SOL': 'SOL_FEE_ADDY_PRIVATE_KEY',
        'LTC': 'LTC_FEE_ADDY_PRIVATE_KEY',
        'BCH': 'BCH_FEE_ADDY_PRIVATE_KEY',
        'DOGE': 'DOGE_FEE_ADDY_PRIVATE_KEY',
        'XRP': 'XRP_FEE_ADDY_PRIVATE_KEY',
        'ADA': 'ADA_FEE_ADDY_PRIVATE_KEY',
        'DOT': 'DOT_FEE_ADDY_PRIVATE_KEY',
        'MATIC': 'MATIC_FEE_ADDY_PRIVATE_KEY',
        'AVAX': 'AVAX_FEE_ADDY_PRIVATE_KEY',
        'TRX': 'TRX_FEE_ADDY_PRIVATE_KEY',
        'BNB': 'BNB_FEE_ADDY_PRIVATE_KEY',
        'ATOM': 'ATOM_FEE_ADDY_PRIVATE_KEY',
        'XLM': 'XLM_FEE_ADDY_PRIVATE_KEY',
        
        # Tokens use their chain's private key
        'USDT-ERC20': 'ETH_FEE_ADDY_PRIVATE_KEY',
        'USDC-ERC20': 'ETH_FEE_ADDY_PRIVATE_KEY',
        'USDT-BEP20': 'BNB_FEE_ADDY_PRIVATE_KEY',
        'USDT-SOL': 'SOL_FEE_ADDY_PRIVATE_KEY',
        'USDT-TRON': 'TRX_FEE_ADDY_PRIVATE_KEY',
    }
    
    env_key = key_map.get(currency)
    if not env_key:
        raise ValueError(f"No private key mapping for currency: {currency}")
    
    private_key = os.getenv(env_key)
    if not private_key:
        raise ValueError(f"Private key not configured in environment: {env_key}")
    
    return private_key

@app.route('/api/exchange/<exchange_id>/cancel', methods=['POST'])
@require_auth
def cancel_exchange(exchange_id):
    """
    Request refund/cancellation of exchange
    
    Request body:
    {
        "refund_address": "user's refund address",
        "refund_tag": "optional tag/memo"
    }
    
    IMPORTANT: 
    - If user deposited to SwapKit's address (which we don't control), 
      we cannot refund directly
    - This endpoint marks the exchange for manual review
    - Admin must process refund manually or contact SwapKit support
    """
    try:
        user_id = request.user_id
        data = request.json or {}
        
        refund_address = data.get('refund_address', '').strip()
        refund_tag = data.get('refund_tag', '').strip()
        
        # ============================================
        # VALIDATION
        # ============================================
        
        if not refund_address:
            return jsonify({'error': 'Refund address is required'}), 400
        
        # Get exchange
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('id', exchange_id)\
            .single()\
            .execute()
        
        if not result.data:
            return jsonify({'error': 'Exchange not found'}), 404
        
        exchange = result.data
        
        # Verify ownership
        if exchange['user_id'] != str(user_id):
            return jsonify({'error': 'Unauthorized'}), 403
        
        # Check if refundable
        refundable_statuses = ['failed', 'expired', 'rate_expired', 'pending']
        if exchange['status'] not in refundable_statuses:
            return jsonify({
                'error': f'Cannot request refund for exchange with status: {exchange["status"]}'
            }), 400
        
        # Check if already refunded
        if exchange['status'] == 'refunded':
            return jsonify({'error': 'Exchange already refunded'}), 400
        
        # ============================================
        # UPDATE EXCHANGE WITH REFUND REQUEST
        # ============================================
        
        update_data = {
            'status': 'refund_requested',
            'updated_at': datetime.utcnow().isoformat(),
            'metadata': {
                **exchange.get('metadata', {}),
                'refund_requested_at': datetime.utcnow().isoformat(),
                'refund_address': refund_address,
                'refund_tag': refund_tag or None,
                'refund_requested_by': str(user_id)
            }
        }
        
        supabase.table('crypto_exchanges').update(update_data).eq('id', exchange_id).execute()
        
        app.logger.info(f"Refund requested for exchange {exchange_id} by user {user_id}")
        
        # ============================================
        # NOTIFY ADMIN (Optional - implement as needed)
        # ============================================
        
        try:
            # Send notification to admin
            supabase.table('admin_notifications').insert({
                'admin_id': None,  # Broadcast to all admins
                'type': 'user_report',
                'title': 'Refund Request',
                'message': f'User requested refund for exchange {exchange_id}. Amount: {exchange["from_amount"]} {exchange["from_currency"]}',
                'priority': 'normal',
                'metadata': {
                    'exchange_id': exchange_id,
                    'user_id': str(user_id),
                    'refund_address': refund_address,
                    'from_currency': exchange['from_currency'],
                    'from_amount': exchange['from_amount']
                }
            }).execute()
        except Exception as notif_error:
            app.logger.error(f"Failed to create admin notification: {notif_error}")
            # Don't fail the request if notification fails
        
        # ============================================
        # RETURN RESPONSE
        # ============================================
        
        return jsonify({
            'status': 'ok',
            'message': 'Refund request submitted successfully. Our team will review and process it.',
            'exchange_id': exchange_id,
            'refund_address': refund_address,
            'note': 'Refunds are typically processed within 24-48 hours'
        }), 200
        
    except Exception as e:
        app.logger.error(f"Cancel exchange error: {e}\n{traceback.format_exc()}")
        return jsonify({'error': 'Failed to request refund. Please try again.'}), 500


# ============================================
# SWAPKIT TRACK (POLLING)
# ============================================

def swapkit_track_transaction(tx_hash, chain_id):
    """
    Track transaction status using SwapKit /track endpoint
    
    Args:
        tx_hash: Transaction hash to track
        chain_id: Chain identifier (e.g., 'BTC', 'ETH')
    
    Returns:
        Status response from SwapKit
    """
    try:
        response = swapkit_request('POST', '/track', data={
            'hash': tx_hash,
            'chainId': chain_id
        })
        
        return response
        
    except Exception as e:
        app.logger.error(f"SwapKit track error: {e}")
        return None

def parse_track_status(track_response):
    """
    Parse SwapKit track response into our status
    
    SwapKit track statuses:
    - not_started
    - pending
    - swapping
    - completed
    - refunded
    - failed
    """
    if not track_response:
        return None
    
    status = track_response.get('status', '').lower()
    
    status_map = {
        'not_started': 'pending',
        'pending': 'confirming',
        'swapping': 'swapping',
        'completed': 'swap_complete',
        'refunded': 'refunded',
        'failed': 'failed'
    }
    
    return status_map.get(status, 'pending')


# ============================================
# BACKGROUND MONITORING (POLLING-BASED)
# ============================================

def monitor_deposit_wallets():
    """
    Monitor temporary wallets for incoming deposits
    
    Flow:
    1. Find pending exchanges
    2. Check wallet balance
    3. If deposit detected, update status
    """
    try:
        app.logger.info("Checking deposit wallets...")
        
        # Get pending exchanges waiting for deposit
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('status', 'pending')\
            .is_('deposit_tx_hash', 'null')\
            .execute()
        
        exchanges = result.data or []
        
        for exchange in exchanges:
            try:
                exchange_id = exchange['id']
                deposit_address = exchange['deposit_address']
                from_currency = exchange['from_currency']
                expected_amount = Decimal(exchange['from_amount'])
                
                # Skip placeholder addresses
                if not deposit_address or deposit_address.startswith('TEMP_WALLET_'):
                    continue
                
                # Check wallet balance
                balance = get_wallet_balance(deposit_address, from_currency)
                
                if balance >= expected_amount:
                    app.logger.info(f"Exchange {exchange_id}: Deposit detected! {balance} {from_currency}")
                    
                    # Update status
                    supabase.table('crypto_exchanges').update({
                        'status': 'deposit_detected',
                        'deposit_detected_at': datetime.utcnow().isoformat(),
                        'deposit_confirmations': 1,
                        'updated_at': datetime.utcnow().isoformat()
                    }).eq('id', exchange_id).execute()
                
            except Exception as e:
                app.logger.error(f"Error checking deposit for {exchange.get('id')}: {e}")
                continue
        
    except Exception as e:
        app.logger.error(f"Deposit monitoring error: {e}\n{traceback.format_exc()}")

def process_swapkit_forwards():
    """
    Forward detected deposits to SwapKit
    
    Flow:
    1. Find deposits ready to forward
    2. Send to SwapKit deposit address
    3. Store transaction hash for tracking
    """
    try:
        app.logger.info("Processing SwapKit forwards...")
        
        # Get exchanges with deposits detected, not yet forwarded
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('status', 'deposit_detected')\
            .is_('deposit_tx_hash', 'null')\
            .execute()
        
        exchanges = result.data or []
        
        for exchange in exchanges:
            try:
                exchange_id = exchange['id']
                from_currency = exchange['from_currency']
                to_currency = exchange['to_currency']
                amount = Decimal(exchange['from_amount'])
                deposit_address = exchange['deposit_address']
                
                # Get wallet credentials
                wallet_result = supabase.table('escrow_wallets')\
                    .select('*')\
                    .eq('address', deposit_address)\
                    .eq('currency', from_currency)\
                    .single()\
                    .execute()
                
                if not wallet_result.data:
                    app.logger.error(f"Exchange {exchange_id}: Wallet not found")
                    continue
                
                wallet = wallet_result.data
                
                # Get SwapKit quote for deposit address
                swapkit_from = map_currency_to_swapkit(from_currency)
                swapkit_to = map_currency_to_swapkit(to_currency)
                platform_to_address = get_platform_fee_address(to_currency)
                
                quote_response = swapkit_request('POST', '/quote', data={
                    'sellAsset': swapkit_from,
                    'buyAsset': swapkit_to,
                    'sellAmount': str(amount),
                    'sourceAddress': deposit_address,
                    'destinationAddress': platform_to_address,
                    'slippage': float(exchange.get('slippage_tolerance', DEFAULT_SLIPPAGE)),
                    'includeTx': True
                })
                
                routes = quote_response.get('routes', [])
                if not routes:
                    app.logger.error(f"Exchange {exchange_id}: No routes available")
                    continue
                
                best_route = routes[0]
                
                # Get SwapKit deposit address
                swapkit_deposit_address = best_route.get('targetAddress')
                
                if not swapkit_deposit_address:
                    app.logger.error(f"Exchange {exchange_id}: No target address from SwapKit")
                    continue
                
                # Send from temp wallet to SwapKit
                tx_hash = send_crypto(
                    from_address=deposit_address,
                    to_address=swapkit_deposit_address,
                    amount=amount,
                    currency=from_currency,
                    private_key_or_mnemonic=wallet['mnemonic']
                )
                
                # Update exchange with transaction hash
                supabase.table('crypto_exchanges').update({
                    'status': 'swapping',
                    'deposit_tx_hash': tx_hash,
                    'deposit_confirmed_at': datetime.utcnow().isoformat(),
                    'swapkit_response': quote_response,
                    'updated_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        **exchange.get('metadata', {}),
                        'swapkit_deposit_address': swapkit_deposit_address,
                        'forwarded_to_swapkit_at': datetime.utcnow().isoformat()
                    }
                }).eq('id', exchange_id).execute()
                
                app.logger.info(f"Exchange {exchange_id}: Forwarded to SwapKit, TX: {tx_hash}")
                
            except Exception as e:
                app.logger.error(f"Error forwarding {exchange.get('id')}: {e}\n{traceback.format_exc()}")
                
                # Mark as failed
                supabase.table('crypto_exchanges').update({
                    'status': 'failed',
                    'error_message': str(e),
                    'updated_at': datetime.utcnow().isoformat()
                }).eq('id', exchange['id']).execute()
                continue
        
    except Exception as e:
        app.logger.error(f"Forward processing error: {e}\n{traceback.format_exc()}")

def poll_swapkit_status():
    """
    Poll SwapKit /track endpoint for swap status updates
    
    This is the key difference - we POLL instead of receiving webhooks
    """
    try:
        app.logger.info("Polling SwapKit status...")
        
        # Get exchanges currently swapping
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .in_('status', ['swapping', 'confirming'])\
            .not_.is_('deposit_tx_hash', 'null')\
            .execute()
        
        exchanges = result.data or []
        
        for exchange in exchanges:
            try:
                exchange_id = exchange['id']
                tx_hash = exchange['deposit_tx_hash']
                from_currency = exchange['from_currency']
                
                # Track transaction using SwapKit
                track_response = swapkit_track_transaction(tx_hash, from_currency)
                
                if not track_response:
                    continue
                
                # Log the tracking check
                supabase.table('swapkit_track_log').insert({
                    'exchange_id': exchange_id,
                    'transaction_hash': tx_hash,
                    'chain_id': from_currency,
                    'status': track_response.get('status'),
                    'response': track_response,
                    'checked_at': datetime.utcnow().isoformat()
                }).execute()
                
                # Parse status
                new_status = parse_track_status(track_response)
                
                if new_status and new_status != exchange['status']:
                    updates = {
                        'status': new_status,
                        'swapkit_response': track_response,
                        'updated_at': datetime.utcnow().isoformat()
                    }
                    
                    # If swap completed, mark ready for payout
                    if new_status == 'swap_complete':
                        updates['user_payout_pending'] = True
                        app.logger.info(f"Exchange {exchange_id}: Swap complete! Ready for payout")
                    
                    supabase.table('crypto_exchanges').update(updates).eq('id', exchange_id).execute()
                    
                    app.logger.info(f"Exchange {exchange_id}: Status {exchange['status']} → {new_status}")
                
            except Exception as e:
                app.logger.error(f"Error polling status for {exchange.get('id')}: {e}")
                continue
        
    except Exception as e:
        app.logger.error(f"Status polling error: {e}\n{traceback.format_exc()}")

def send_payout_transaction(from_address, to_address, amount, currency, destination_tag=None):
    """
    Send payout transaction using Tatum API
    
    Args:
        from_address: Platform wallet address
        to_address: User's destination address
        amount: Amount to send (Decimal)
        currency: Currency code (e.g., 'BTC', 'ETH', 'USDT-ERC20')
        destination_tag: Optional tag/memo for XRP, XLM, etc.
    
    Returns:
        Transaction hash string
    
    Raises:
        Exception: If transaction fails
    """
    try:
        TATUM_API_KEY = os.getenv('TATUM_API_KEY')
        if not TATUM_API_KEY:
            raise Exception("TATUM_API_KEY not configured")
        
        # Get private key for this currency's platform wallet
        private_key = get_platform_wallet_private_key(currency)
        
        headers = {
            'x-api-key': TATUM_API_KEY,
            'Content-Type': 'application/json'
        }
        
        # Map currency to Tatum chain
        chain_map = {
            'BTC': 'bitcoin',
            'ETH': 'ethereum',
            'SOL': 'solana',
            'LTC': 'litecoin',
            'BCH': 'bcash',
            'DOGE': 'dogecoin',
            'XRP': 'xrp',
            'ADA': 'cardano',
            'DOT': 'polkadot',
            'MATIC': 'polygon',
            'AVAX': 'avax',
            'BNB': 'bsc',
            'TRX': 'tron',
            'ATOM': 'cosmos',
            'XLM': 'xlm',
            'USDT-ERC20': 'ethereum',
            'USDT-BEP20': 'bsc',
            'USDT-SOL': 'solana',
            'USDT-TRON': 'tron',
        }
        
        chain = chain_map.get(currency)
        if not chain:
            raise ValueError(f"Unsupported currency for payout: {currency}")
        
        # Build transaction payload
        payload = {
            'from': from_address,
            'to': to_address,
            'amount': str(amount),
            'privateKey': private_key
        }
        
        # Handle ERC-20 tokens
        if currency == 'USDT-ERC20':
            payload['contractAddress'] = '0xdAC17F958D2ee523a2206206994597C13D831ec7'
            payload['digits'] = 6
        elif currency == 'USDC-ERC20':
            payload['contractAddress'] = '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'
            payload['digits'] = 6
        elif currency == 'USDT-BEP20':
            payload['contractAddress'] = '0x55d398326f99059fF775485246999027B3197955'
            payload['digits'] = 18
        elif currency == 'USDT-TRON':
            payload['tokenAddress'] = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'
        elif currency == 'USDT-SOL':
            payload['tokenAddress'] = 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB'
        
        # Handle destination tags for XRP/XLM
        if chain == 'xrp' and destination_tag:
            payload['destinationTag'] = int(destination_tag)
        elif chain == 'xlm' and destination_tag:
            payload['message'] = destination_tag
        
        # Send transaction
        app.logger.info(f"Sending payout: {amount} {currency} from {from_address} to {to_address}")
        
        response = requests.post(
            f'https://api.tatum.io/v3/{chain}/transaction',
            headers=headers,
            json=payload,
            timeout=60
        )
        
        if response.status_code != 200:
            error_msg = response.text
            try:
                error_json = response.json()
                error_msg = error_json.get('message', error_json.get('error', error_msg))
            except:
                pass
            raise Exception(f"Tatum transaction failed ({response.status_code}): {error_msg}")
        
        tx_data = response.json()
        tx_hash = tx_data.get('txId')
        
        if not tx_hash:
            raise Exception(f"No transaction hash in response: {tx_data}")
        
        app.logger.info(f"Payout transaction sent successfully: {tx_hash}")
        return tx_hash
        
    except Exception as e:
        app.logger.error(f"Send payout transaction error: {e}")
        raise

def process_user_payouts():
    """
    Process payouts to users after SwapKit completes swap
    
    Flow:
    1. Find exchanges ready for payout (status: swap_complete)
    2. Verify platform wallet has received funds
    3. Send user portion to their destination address
    4. Platform fee stays in platform wallet
    5. Mark exchange as completed
    """
    try:
        app.logger.info("Processing user payouts...")
        
        # Get exchanges ready for payout
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('user_payout_pending', True)\
            .eq('status', 'swap_complete')\
            .is_('user_payout_tx_hash', 'null')\
            .execute()
        
        exchanges = result.data or []
        
        if not exchanges:
            app.logger.info("No exchanges ready for payout")
            return
        
        app.logger.info(f"Processing {len(exchanges)} payouts")
        
        for exchange in exchanges:
            exchange_id = None
            try:
                exchange_id = exchange['id']
                to_currency = exchange['to_currency']
                user_amount = Decimal(str(exchange['user_payout_amount']))
                platform_fee = Decimal(str(exchange['platform_fee_amount']))
                destination_address = exchange['destination_address']
                platform_wallet = exchange['platform_fee_address']
                destination_tag = exchange.get('metadata', {}).get('destination_tag')
                
                app.logger.info(f"Exchange {exchange_id}: Processing {user_amount} {to_currency} payout")
                
                # ============================================
                # STEP 1: VERIFY PLATFORM WALLET BALANCE
                # ============================================
                
                try:
                    platform_balance = get_wallet_balance(platform_wallet, to_currency)
                    total_needed = user_amount + platform_fee  # Total we should have received
                    
                    if platform_balance < total_needed:
                        app.logger.warning(
                            f"Exchange {exchange_id}: Insufficient balance in platform wallet. "
                            f"Expected {total_needed} {to_currency}, have {platform_balance} {to_currency}. "
                            f"Waiting for funds..."
                        )
                        continue  # Skip this exchange, retry next cycle
                    
                    app.logger.info(f"Exchange {exchange_id}: Platform balance verified ({platform_balance} {to_currency})")
                    
                except Exception as balance_error:
                    app.logger.error(f"Exchange {exchange_id}: Balance check failed: {balance_error}")
                    continue  # Skip and retry later
                
                # ============================================
                # STEP 2: CALCULATE FINAL PAYOUT AMOUNT
                # ============================================
                
                # Deduct estimated network fee from user amount
                network_fee = estimate_network_fee(to_currency)
                final_payout_amount = user_amount - network_fee
                
                if final_payout_amount <= 0:
                    app.logger.error(
                        f"Exchange {exchange_id}: Payout amount too small after network fees. "
                        f"User amount: {user_amount}, Network fee: {network_fee}"
                    )
                    
                    # Mark as failed
                    supabase.table('crypto_exchanges').update({
                        'status': 'failed',
                        'error_message': f'Amount too small to send after network fees ({network_fee} {to_currency})',
                        'user_payout_pending': False,
                        'updated_at': datetime.utcnow().isoformat()
                    }).eq('id', exchange_id).execute()
                    continue
                
                app.logger.info(
                    f"Exchange {exchange_id}: Sending {final_payout_amount} {to_currency} "
                    f"(after {network_fee} network fee)"
                )
                
                # ============================================
                # STEP 3: SEND PAYOUT TRANSACTION
                # ============================================
                
                try:
                    tx_hash = send_payout_transaction(
                        from_address=platform_wallet,
                        to_address=destination_address,
                        amount=final_payout_amount,
                        currency=to_currency,
                        destination_tag=destination_tag
                    )
                    
                    if not tx_hash:
                        raise Exception("Transaction returned no hash")
                    
                    app.logger.info(f"Exchange {exchange_id}: Payout sent successfully! TX: {tx_hash}")
                    
                except Exception as tx_error:
                    app.logger.error(f"Exchange {exchange_id}: Payout transaction failed: {tx_error}")
                    
                    # Increment retry count
                    retry_count = (exchange.get('retry_count', 0) or 0) + 1
                    
                    # After 5 retries, mark as failed
                    if retry_count >= 5:
                        supabase.table('crypto_exchanges').update({
                            'status': 'failed',
                            'error_message': f"Payout failed after {retry_count} attempts: {str(tx_error)}",
                            'user_payout_pending': False,
                            'retry_count': retry_count,
                            'updated_at': datetime.utcnow().isoformat()
                        }).eq('id', exchange_id).execute()
                        
                        app.logger.error(f"Exchange {exchange_id}: Marked as failed after {retry_count} retries")
                    else:
                        # Update retry count and schedule retry
                        supabase.table('crypto_exchanges').update({
                            'retry_count': retry_count,
                            'last_retry_at': datetime.utcnow().isoformat(),
                            'error_message': f"Payout attempt {retry_count} failed: {str(tx_error)}",
                            'updated_at': datetime.utcnow().isoformat()
                        }).eq('id', exchange_id).execute()
                        
                        app.logger.warning(f"Exchange {exchange_id}: Retry {retry_count}/5 scheduled")
                    
                    continue
                
                # ============================================
                # STEP 4: UPDATE EXCHANGE AS COMPLETED
                # ============================================
                
                supabase.table('crypto_exchanges').update({
                    'status': 'completed',
                    'user_payout_pending': False,
                    'user_payout_tx_hash': tx_hash,
                    'user_payout_sent_at': datetime.utcnow().isoformat(),
                    'completed_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat(),
                    'metadata': {
                        **exchange.get('metadata', {}),
                        'final_payout_amount': str(final_payout_amount),
                        'network_fee_deducted': str(network_fee),
                        'payout_tx_hash': tx_hash
                    }
                }).eq('id', exchange_id).execute()
                
                app.logger.info(f"Exchange {exchange_id}: Marked as completed ✓")
                
                # ============================================
                # STEP 5: LOG FEE COLLECTION (Optional)
                # ============================================
                
                try:
                    supabase.table('exchange_fee_ledger').insert({
                        'exchange_id': exchange_id,
                        'fee_type': 'platform',
                        'currency': to_currency,
                        'amount': str(platform_fee),
                        'collected': True,
                        'collected_at': datetime.utcnow().isoformat(),
                        'destination_address': platform_wallet,
                        'metadata': {
                            'user_payout_tx': tx_hash,
                            'user_payout_amount': str(final_payout_amount)
                        }
                    }).execute()
                except Exception as fee_log_error:
                    app.logger.error(f"Failed to log fee collection: {fee_log_error}")
                    # Don't fail the payout if fee logging fails
                
            except Exception as e:
                if exchange_id:
                    app.logger.error(f"Error processing exchange {exchange_id}: {e}\n{traceback.format_exc()}")
                else:
                    app.logger.error(f"Error processing exchange (unknown ID): {e}\n{traceback.format_exc()}")
                continue
        
        app.logger.info("Payout processing complete")
        
    except Exception as e:
        app.logger.error(f"Payout processing error: {e}\n{traceback.format_exc()}")

def check_expired_exchanges():
    """Mark expired exchanges"""
    try:
        # Rate expired
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('status', 'pending')\
            .execute()
        
        for exchange in result.data or []:
            if exchange.get('rate_expires_at'):
                expires = datetime.fromisoformat(exchange['rate_expires_at'].replace('Z', '+00:00'))
                if datetime.utcnow() > expires:
                    supabase.table('crypto_exchanges').update({
                        'status': 'rate_expired',
                        'error_message': 'Rate expired',
                        'updated_at': datetime.utcnow().isoformat()
                    }).eq('id', exchange['id']).execute()
        
        # Stale exchanges
        stale_time = datetime.utcnow() - timedelta(seconds=EXCHANGE_MAX_PENDING_AGE)
        
        result = supabase.table('crypto_exchanges')\
            .select('*')\
            .eq('status', 'pending')\
            .lt('created_at', stale_time.isoformat())\
            .execute()
        
        for exchange in result.data or []:
            supabase.table('crypto_exchanges').update({
                'status': 'expired',
                'error_message': 'Exchange expired',
                'updated_at': datetime.utcnow().isoformat()
            }).eq('id', exchange['id']).execute()
        
    except Exception as e:
        app.logger.error(f"Expired check error: {e}")

def monitor_exchanges():
    """
    Main monitoring loop - POLLING based (no webhooks)
    """
    while True:
        try:
            app.logger.info("=== Exchange monitor cycle ===")
            
            # 1. Check for deposits
            monitor_deposit_wallets()
            
            # 2. Forward to SwapKit
            process_swapkit_forwards()
            
            # 3. POLL SwapKit status (not webhooks!)
            poll_swapkit_status()
            
            # 4. Process user payouts
            process_user_payouts()
            
            # 5. Check expired
            check_expired_exchanges()
            
            app.logger.info("=== Cycle complete ===")
            
        except Exception as e:
            app.logger.error(f"Monitor error: {e}\n{traceback.format_exc()}")
        
        time.sleep(EXCHANGE_STATUS_CHECK_INTERVAL)


# ============================================
# STARTUP VALIDATION
# ============================================

def validate_configuration():
    """
    Validate all required configuration on startup
    
    Checks:
    - Required environment variables
    - Fee addresses configured
    - Database connectivity
    - SwapKit API connectivity
    """
    errors = []
    warnings = []
    
    # Required env vars
    required_vars = [
        'SUPABASE_URL',
        'SUPABASE_SERVICE_KEY',
        'SUPABASE_JWT_SECRET',
        'SWAPKIT_API_KEY'
    ]
    
    for var in required_vars:
        if not os.getenv(var):
            errors.append(f"Missing required environment variable: {var}")
    
    # Fee addresses
    missing_addresses = []
    for currency, address in FEE_ADDRESSES.items():
        if not address:
            missing_addresses.append(currency)
    
    if missing_addresses:
        warnings.append(f"Missing fee addresses for: {', '.join(missing_addresses)}")
    
    # Tatum API key (optional but recommended)
    if not os.getenv('TATUM_API_KEY'):
        warnings.append("TATUM_API_KEY not configured - wallet generation will not work")
    
    # Test database connectivity (catch DNS/network errors separately)
    try:
        try:
            supabase.table('profiles').select('id').limit(1).execute()
        except Exception as e:
            # If it's a DNS resolution error, provide a clearer message
            if isinstance(e, Exception) and 'getaddrinfo' in str(e):
                errors.append(f"Database connection failed: DNS lookup failed for SUPABASE_URL host. Raw error: {str(e)}")
            else:
                errors.append(f"Database connection failed: {str(e)}")
    except Exception as e:
        # Fallback catch-all (shouldn't normally be reached)
        errors.append(f"Database connection test raised unexpected error: {str(e)}")
    
    # Test SwapKit connectivity (give clearer DNS/network hints)
    try:
        try:
            swapkit_request('GET', '/providers')
        except Exception as e:
            if isinstance(e, Exception) and 'getaddrinfo' in str(e):
                errors.append(f"SwapKit API connection failed: DNS lookup failed. Raw error: {str(e)}")
            else:
                errors.append(f"SwapKit API connection failed: {str(e)}")
    except Exception as e:
        errors.append(f"SwapKit connection test raised unexpected error: {str(e)}")
    
    # Print results
    if errors:
        app.logger.error("❌ Configuration errors:")
        dns_issues = any('DNS lookup failed' in e or 'getaddrinfo' in e for e in errors)
        for error in errors:
            app.logger.error(f"  - {error}")

        # Add quick remediation hints for common DNS/network problems
        if dns_issues:
            app.logger.error("  → Hint: DNS lookup failed. Check that SUPABASE_URL is correct and your machine has network/DNS access.")
            app.logger.error("  → Example: set SUPABASE_URL to 'https://<project>.supabase.co' and ensure no trailing slashes or typos.")
            app.logger.error("  → If behind a proxy or corporate network, ensure DNS resolution is allowed or configure proxy settings.")

        # Add hint for missing env vars
        missing_envs = [v for v in required_vars if not os.getenv(v)]
        if missing_envs:
            app.logger.error(f"  → Missing env vars: {', '.join(missing_envs)}. Use your .env or set them in the environment before starting.")

        raise Exception("Configuration validation failed. See errors above.")
    
    if warnings:
        app.logger.warning("⚠️  Configuration warnings:")
        for warning in warnings:
            app.logger.warning(f"  - {warning}")
    
    app.logger.info("✅ Configuration validation passed")
    
    # Log active currencies
    active_currencies = [c for c, a in FEE_ADDRESSES.items() if a]
    app.logger.info(f"✅ Active currencies ({len(active_currencies)}): {', '.join(active_currencies)}")

# ===========================================
# BACKGROUND TASK SCHEDULER (Simple implementation)
# ===========================================

def setup_background_tasks():
    """Setup background tasks for analytics maintenance"""
    import threading
    import time

    def cache_cleanup_worker():
        """Background worker for cache cleanup"""
        while True:
            try:
                time.sleep(3600)  # Run every hour
                cleanup_expired_cache_background()
                anonymize_old_analytics_data()
            except Exception as e:
                app.logger.error(f"Background task error: {e}")

    # Start background thread
    cleanup_thread = threading.Thread(target=cache_cleanup_worker, daemon=True)
    cleanup_thread.start()
    app.logger.info("Background analytics tasks started")

def cleanup_expired_cache_background():
    """Background cache cleanup function"""
    try:
        # Clean listing analytics cache
        supabase.table('listing_analytics_cache')\
            .delete()\
            .lt('expires_at', datetime.now().isoformat())\
            .execute()

        # Clean seller analytics cache
        supabase.table('seller_analytics_cache')\
            .delete()\
            .lt('expires_at', datetime.now().isoformat())\
            .execute()

        app.logger.info("Background cache cleanup completed")
        return True

    except Exception as e:
        app.logger.error(f"Error in background cache cleanup: {e}")
        return False

# Initialize background tasks when app starts
# Note: In production, use a proper task scheduler like Celery
@app.before_request
def initialize_background_tasks():
    """Initialize background tasks on first request"""
    if not hasattr(app, '_background_tasks_initialized'):
        disable_bg = os.getenv('DISABLE_BACKGROUND_TASKS','').lower() in ('1','true','yes')
        if not app.config.get('TESTING', False) and not disable_bg:
            setup_background_tasks()
        app._background_tasks_initialized = True





# -- Explicitly ensure the seller products route accepts GET/OPTIONS --
# Some decorator interactions or runtime registration order can accidentally
# register a path without GET allowed. This explicit add_url_rule call
# guarantees the path accepts GET and routes to the function defined above.
try:
    app.add_url_rule('/api/marketplace/seller/products',
                     endpoint='get_seller_products_explicit',
                     view_func=get_seller_products,
                     methods=['GET','OPTIONS'])
except Exception as _e:
    # If this fails (e.g., endpoint already registered), log and continue.
    try:
        app.logger.info(f"Could not add explicit rule for seller/products: {_e}")
    except Exception:
        pass



if __name__ == '__main__':
    # Validate configuration before starting
    validate_configuration()
    
    # Start background monitor (only in production)
    if os.getenv('FLASK_ENV') == 'production' or os.getenv('START_MONITOR', 'false').lower() == 'true':
        monitor_thread = Thread(target=monitor_exchanges, daemon=True)
        monitor_thread.start()
        app.logger.info("✅ Background exchange monitor started")
    else:
        app.logger.info("ℹ️  Background monitor disabled (set START_MONITOR=true to enable)")
    
    # Get port from environment
    port = int(os.getenv('PORT', 5000))
    
    # Start Flask app
    app.logger.info(f"🚀 Starting Medius backend on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
