#!/usr/bin/env python3
"""
Test script to verify the seller products route is working correctly.
"""
import os
import requests
import json

# Test the route with curl-like behavior
def test_route():
    # Set fake environment variables to avoid import issues
    os.environ['SUPABASE_URL'] = 'https://fake-project.supabase.co'
    os.environ['SUPABASE_SERVICE_KEY'] = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake'
    os.environ['SUPABASE_JWT_SECRET'] = 'fake-secret-key-for-testing'

    try:
        import sys
        sys.path.append('backend')
        from app import app

        print("✅ Successfully imported Flask app")
        print("\nRoutes containing 'seller/products':")

        found_routes = []
        for rule in app.url_map.iter_rules():
            if 'seller/products' in rule.rule:
                found_routes.append((rule.rule, sorted(rule.methods)))

        if found_routes:
            for rule, methods in found_routes:
                print(f"  📍 {rule} -> {methods}")
                if 'GET' in methods:
                    print("  ✅ GET method is registered!"                else:
                    print("  ❌ GET method is NOT registered!"        else:
            print("  ❌ No routes found containing 'seller/products'")

        print(f"\nTotal routes in app: {len(list(app.url_map.iter_rules()))}")

        # Check for conflicting OPTIONS routes
        print("\nChecking for OPTIONS route conflicts:")
        options_routes = []
        for rule in app.url_map.iter_rules():
            if rule.rule == '/api/marketplace/seller/products' and 'OPTIONS' in rule.methods:
                options_routes.append((rule.rule, rule.endpoint))

        if len(options_routes) > 1:
            print("  ⚠️  Multiple OPTIONS routes found - this could cause conflicts:")
            for rule, endpoint in options_routes:
                print(f"    - {rule} -> {endpoint}")
        elif len(options_routes) == 1:
            print("  ✅ Single OPTIONS route found (good)")
        else:
            print("  ℹ️  No specific OPTIONS route (using global handler)")

    except Exception as e:
        print(f"❌ Error testing route: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_route()

