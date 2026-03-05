# TLS Termination Guide

This guide covers production TLS termination for Prompt Sentinel behind a reverse proxy.

## Architecture

- Public traffic terminates TLS at `nginx` or `Caddy`.
- Reverse proxy forwards plain HTTP to Prompt Sentinel on a private network.
- Prompt Sentinel sets strict security headers and trusts proxy-forwarded host/proto metadata.

## Required Headers From Proxy

Forward these headers to Prompt Sentinel:

- `X-Forwarded-Proto`
- `X-Forwarded-For`
- `X-Forwarded-Host`
- `Host`

## Nginx Example

```nginx
server {
    listen 443 ssl http2;
    server_name api.example.com;

    ssl_certificate /etc/letsencrypt/live/api.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    location / {
        proxy_pass http://prompt-sentinel:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

## Caddy Example

```caddyfile
api.example.com {
    reverse_proxy prompt-sentinel:3000 {
        header_up Host {http.request.host}
        header_up X-Forwarded-For {http.request.remote}
        header_up X-Forwarded-Proto {http.request.scheme}
        header_up X-Forwarded-Host {http.request.host}
    }
}
```

## Operational Notes

- Keep Prompt Sentinel private (`0.0.0.0:3000` only inside trusted network or Kubernetes cluster).
- Rotate certificates automatically (Let's Encrypt ACME).
- Restrict inbound traffic so only the reverse proxy can reach Prompt Sentinel.
- Use `/health/live`, `/health/ready`, and `/health/startup` for load balancer and Kubernetes probes.
