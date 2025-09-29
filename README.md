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
curl -X PUT -d '{"username":"admin"}' -H "Content-Type: application/json"   "https://your-worker.account.workers.dev?url=https://httpbin.org/put"

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
