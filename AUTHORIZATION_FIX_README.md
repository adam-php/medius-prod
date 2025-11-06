# Fixing "No Authorization Header" Issues

This guide provides comprehensive solutions for CORS and authorization header issues commonly encountered when developing with Next.js frontend and Flask backend, especially when using ngrok for development.

## Quick Diagnosis

### 1. Check the Debug Endpoint
Visit: `https://your-api-url.ngrok-free.app/api/debug/auth`

This endpoint provides detailed information about:
- Whether Authorization headers are being received
- CORS configuration status
- Environment variable setup
- Troubleshooting suggestions

### 2. Browser Network Tab Check
1. Open browser Developer Tools → Network tab
2. Make a request that requires authentication
3. Check the Request Headers section
4. Verify `Authorization: Bearer <token>` is present

## Common Issues & Solutions

### Issue 1: Mixed Content (HTTP/HTTPS Mismatch)
**Problem**: Frontend is HTTPS (ngrok) but API URL is HTTP
**Solution**: Ensure NEXT_PUBLIC_API_URL uses HTTPS for ngrok:

```bash
# Wrong
NEXT_PUBLIC_API_URL=http://xxxxx.ngrok-free.app

# Correct
NEXT_PUBLIC_API_URL=https://xxxxx.ngrok-free.app
```

### Issue 2: Missing Environment Variables
**Problem**: SUPABASE_JWT_SECRET not set
**Solution**: Create `.env` file in backend directory:

```bash
cp backend/env-example.txt backend/.env
# Edit .env with your actual values
```

Required variables:
- `SUPABASE_JWT_SECRET` - From Supabase project settings
- `CORS_ALLOW_ALL=true` - For development
- `FLASK_ENV=development`

### Issue 3: CORS Not Allowing Authorization Headers
**Problem**: Backend CORS configuration blocking Authorization header
**Solution**: Already fixed in the updated backend. The CORS configuration now includes:

```python
allow_headers=["Authorization", "Content-Type", "ngrok-skip-browser-warning", "Accept", "User-Agent", "X-Requested-With", "Cache-Control", "X-CSRF-Token"]
```

### Issue 4: Proxy Stripping Headers
**Problem**: nginx, cloud proxy, or ngrok stripping Authorization headers
**Solution**: If using nginx, add to configuration:

```nginx
proxy_set_header Authorization $http_authorization;
proxy_set_header Content-Type $http_content_type;
proxy_pass_header Authorization;
```

### Issue 5: Frontend Not Sending Headers Correctly
**Problem**: Frontend API functions not configured properly
**Solution**: The updated `api.ts` includes:
- Proper `mode: "cors"`
- Automatic HTTPS conversion for ngrok URLs
- Enhanced error handling
- Better token validation

## Testing Steps

### 1. Test Health Endpoint (No Auth Required)
```bash
curl https://your-api-url.ngrok-free.app/api/health
```

### 2. Test Debug Endpoint
```bash
curl -H "Authorization: Bearer test" https://your-api-url.ngrok-free.app/api/debug/auth
```

### 3. Full Authentication Test
1. Login to your frontend application
2. Open browser Network tab
3. Make an authenticated request
4. Check that Authorization header is sent
5. Verify backend receives it (check server logs)

## Environment Setup

### Backend (.env)
```bash
# Required
SUPABASE_JWT_SECRET=your_jwt_secret
CORS_ALLOW_ALL=true
FLASK_ENV=development

# Optional
FRONTEND_URL=http://localhost:3000
ADDITIONAL_ALLOWED_ORIGINS=https://yourdomain.com
```

### Frontend (.env.local)
```bash
# Required
NEXT_PUBLIC_API_URL=https://xxxxx.ngrok-free.app
NEXT_PUBLIC_SUPABASE_URL=your_supabase_url
NEXT_PUBLIC_SUPABASE_ANON_KEY=your_anon_key

# Optional
NEXT_PUBLIC_SITE_URL=http://localhost:3000
```

## Debug Checklist

- [ ] NEXT_PUBLIC_API_URL includes `https://` for ngrok
- [ ] SUPABASE_JWT_SECRET is set in backend
- [ ] CORS_ALLOW_ALL=true for development
- [ ] Browser sends Authorization header (check Network tab)
- [ ] Backend receives Authorization header (check `/api/debug/auth`)
- [ ] No mixed content warnings in console
- [ ] ngrok-skip-browser-warning header is sent
- [ ] User-Agent header is present

## Updated Features

### Enhanced Error Messages
The backend now provides detailed error messages with troubleshooting steps for:
- Missing Authorization headers
- Invalid token format
- Expired tokens
- Server configuration errors

### Improved CORS Configuration
- Extended max_age to 24 hours
- Added more allowed headers
- Better error handling for preflight requests

### Frontend Improvements
- Automatic HTTPS conversion for ngrok URLs
- Better session validation
- Enhanced error handling with troubleshooting info

### Debug Endpoints
- `/api/health` - Basic health check (no auth)
- `/api/debug/auth` - Comprehensive auth debugging

## Still Having Issues?

1. Check the `/api/debug/auth` endpoint for detailed diagnostics
2. Review browser console for CORS errors
3. Check backend server logs for detailed error information
4. Verify all environment variables are set correctly
5. Test with a simple curl command to isolate frontend vs backend issues

## Example Working Configuration

### Backend (app.py)
```python
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "allow_headers": ["Authorization", "Content-Type", "ngrok-skip-browser-warning"],
        "methods": ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        "max_age": 86400
    }
}, supports_credentials=False)
```

### Frontend (api.ts)
```typescript
const headers = {
  "Authorization": `Bearer ${session.access_token}`,
  "ngrok-skip-browser-warning": "true",
  "Content-Type": "application/json"
};

return fetch(url, {
  mode: "cors",
  credentials: "omit",
  headers
});
```


