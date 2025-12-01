# SocksFlareProx 🔥

**SOCKS + HTTP proxying via Cloudflare Workers** 

SocksFlareProx deploys HTTP proxy endpoints on Cloudflare Workers and can run local SOCKS proxies that route traffic through those workers. It supports all HTTP methods (GET, POST, PUT, DELETE, etc.) and provides IP masking through Cloudflare's global network. 100k requests per day are free!

Inspired by the original FlareProx project by @MrTurvey (MIT License).

## Features

- **HTTP Support**: All HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- **SOCKS Mode**: Local SOCKS proxies that tunnel traffic through your worker endpoints
- **Simple URL Redirection**: Provide any URL and SocksFlareProx proxies it through Cloudflare
- **Global Network**: Leverage Cloudflare's worldwide CDN infrastructure
- **Free Tier**: 100,000 requests per day on Cloudflare's free plan
- **Easy Deployment**: Single command deployment and management

## How It Works

SocksFlareProx deploys Cloudflare Workers that act as HTTP proxies and can optionally run local SOCKS proxies for broader TCP traffic.

**HTTP mode**

1. **Request Routing**: Your request is sent to a SocksFlareProx endpoint
2. **URL Extraction**: The Worker extracts the target URL from query params or custom HTTP header
3. **Request Proxying**: The Worker forwards your request to the target URL
4. **Response Relay**: The target's response is relayed back through Cloudflare
5. **IP Masking**: Your original IP is masked by Cloudflare's infrastructure

**SOCKS mode (local)**
1. **Local Proxy**: Start a local SOCKS proxy bound to localhost
2. **Tunnel Setup**: SocksFlareProx establishes a tunnel to your worker endpoint
3. **Traffic Relay**: TCP traffic is relayed through Cloudflare to the target

## Screenshots
### Create Proxies:
![List](screenshots/proxyscreate.png "list")
### Test Proxies:
![Usage](screenshots/proxys.png "usage")
### Using a Proxy with BurpSuite:
![Create](screenshots/request.png "create")

## Quick Start

### 1. Install Dependencies
```bash
git clone <repository-url>
cd socksflareprox
pip install -r requirements.txt
```

### 2. Configure Cloudflare Access

Run `python3 flareprox.py config` or directly edit `flareprox.json` in the project directory:
```json
{
  "cloudflare": {
    "api_token": "your_cloudflare_api_token",
    "account_id": "your_cloudflare_account_id"
  }
}
```

### 3. Deploy Proxy Endpoints
```bash
# Create 2 proxy endpoints
python3 flareprox.py create --count 2

# View deployed endpoints
python3 flareprox.py list
```

### 4. Use Your Proxies
```bash
# Test all endpoints are functioning
python3 flareprox.py test

# Example per HTTP Method

# GET request
curl "https://your-worker.account.workers.dev?url=https://httpbin.org/get"

# POST request with data
curl -X POST -d "username=admin" "https://your-worker.account.workers.dev?url=https://httpbin.org/post"

# PUT request with JSON
curl -X PUT -d '{"username":"admin"}' -H "Content-Type: application/json" \
  "https://your-worker.account.workers.dev?url=https://httpbin.org/put"

# DELETE request
curl -X DELETE "https://your-worker.account.workers.dev?url=https://httpbin.org/delete"
```
Each deployed SocksFlareProx endpoint accepts requests in two formats:

```bash
# Query parameter
curl "https://your-worker.account.workers.dev?url=https://httpbin.org/ip"

# Custom header
curl -H "X-Target-URL: https://httpbin.org/ip" https://your-worker.account.workers.dev
```

### 5. SOCKS Mode (Local)
```bash
# Start a local SOCKS proxy bound to localhost
python3 flareprox.py socks --bind 127.0.0.1 --start-port 1080
```
Point your client at `127.0.0.1:1080` to route traffic through SocksFlareProx.

### 6. Proxy Cleanup
```bash
# Delete all proxy endpoints
python3 flareprox.py cleanup
```


## Getting Cloudflare Credentials

### Cloudflare Workers Setup
1. Sign up at [Cloudflare](https://cloudflare.com)
2. Go to [API Tokens](https://dash.cloudflare.com/profile/api-tokens)
3. Click 'Create Token' and use the 'Edit Cloudflare Workers' template
4. Set the 'account resources' and 'zone resources' to all. Click 'Continue to Summary'
5. Click 'Create Token' and copy the token and your Account ID from the dashboard


## Programmatic Usage

SocksFlareProx can be imported and used directly in your Python applications (the module and class names remain `flareprox` / `FlareProx`). Here's how to send a POST request:

```python
#!/usr/bin/env python3
from flareprox import FlareProx, FlareProxError
import json

# Initialize SocksFlareProx client
flareprox = FlareProx(config_file="flareprox.json")

# Check if configured
if not flareprox.is_configured:
    print("SocksFlareProx not configured. Run: python3 flareprox.py config")
    exit(1)

# Create some endpoints if none exist
endpoints = flareprox.sync_endpoints()
if not endpoints:
    print("Creating proxy endpoints...")
    flareprox.create_proxies(count=2)

# Make a POST request through SocksFlareProx
try:
    # Prepare POST data
    post_data = json.dumps({
        "username": "testuser",
        "message": "Hello from SocksFlareProx!",
        "timestamp": "2025-01-01T12:00:00Z"
    })

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "SocksFlareProx-Client/1.0"
    }

    # Send POST request via random SocksFlareProx endpoint
    response = flareprox.redirect_request(
        target_url="https://httpbin.org/post",
        method="POST",
        headers=headers,
        data=post_data
    )

    if response.status_code == 200:
        result = response.json()
        print(f"✓ POST successful via SocksFlareProx")
        print(f"Origin IP: {result.get('origin', 'unknown')}")
        print(f"Posted data: {result.get('json', {})}")
    else:
        print(f"Request failed with status: {response.status_code}")

except FlareProxError as e:
    print(f"SocksFlareProx error: {e}")
except Exception as e:
    print(f"Request error: {e}")
```


## Use Cases

- **API Development**: Test APIs through different IP addresses
- **Web Scraping**: Route requests through Cloudflare's network
- **Security Testing**: Mask your origin IP during testing
- **Load Testing**: Distribute requests across multiple endpoints
- **Privacy**: Add an extra layer between your requests and target servers

## Disclaimer

SocksFlareProx is designed for legitimate development, testing, and research purposes. Users are responsible for ensuring their usage complies with applicable laws and terms of service. The authors assume no liability for misuse of this tool.

---
