#!/usr/bin/env python3
"""
Quick authentication test to verify the actual behavior
"""

import asyncio
import aiohttp
import os
from dotenv import load_dotenv

load_dotenv('/app/frontend/.env')

async def test_auth():
    base_url = os.getenv('REACT_APP_BACKEND_URL', 'http://localhost:8001')
    api_url = f"{base_url}/api"
    
    async with aiohttp.ClientSession() as session:
        # Test without API key
        print("Testing POST /api/merchant without API key...")
        async with session.post(f"{api_url}/merchant", json={"domain": "test.com"}) as response:
            print(f"Status: {response.status}")
            text = await response.text()
            print(f"Response: {text}")
        
        # Test with invalid API key
        print("\nTesting POST /api/merchant with invalid API key...")
        headers = {"X-API-Key": "invalid-key"}
        async with session.post(f"{api_url}/merchant", json={"domain": "test.com"}, headers=headers) as response:
            print(f"Status: {response.status}")
            text = await response.text()
            print(f"Response: {text}")

if __name__ == "__main__":
    asyncio.run(test_auth())