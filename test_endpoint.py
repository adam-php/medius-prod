#!/usr/bin/env python3
import requests
import time

# Wait for server to start
time.sleep(3)

print("Testing GET /api/marketplace/seller/products without auth...")
try:
    r = requests.get('http://localhost:5000/api/marketplace/seller/products')
    print(f"Status: {r.status_code}")
    print(f"Allow header: {r.headers.get('Allow', 'Not present')}")
    print(f"Server: {r.headers.get('Server', 'Unknown')}")
    print(f"Response length: {len(r.text)}")
    if r.status_code != 405:
        print("SUCCESS: Request worked!")
    else:
        print("FAILED: Still getting 405")
except Exception as e:
    print(f"Error: {e}")

print("\nTesting OPTIONS request...")
try:
    r = requests.options('http://localhost:5000/api/marketplace/seller/products')
    print(f"Status: {r.status_code}")
    print(f"Allow header: {r.headers.get('Allow', 'Not present')}")
except Exception as e:
    print(f"Error: {e}")

print("\nTesting GET with dummy auth header...")
try:
    headers = {'Authorization': 'Bearer dummy_token'}
    r = requests.get('http://localhost:5000/api/marketplace/seller/products', headers=headers)
    print(f"Status: {r.status_code}")
    print(f"Allow header: {r.headers.get('Allow', 'Not present')}")
except Exception as e:
    print(f"Error: {e}")
















