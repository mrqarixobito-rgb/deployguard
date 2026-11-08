"""Fix guides: numbered steps, ready-to-paste code per server type, and a terminal command to verify."""

PLATFORMS = [("nginx", "Nginx"), ("apache", "Apache"), ("django", "Django"), ("express", "Node / Express"), ("static", "Netlify / Vercel")]
PLATFORM_KEYS = [k for k, _ in PLATFORMS]

HEADER_VALUES = {
    "hsts": ("Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    "csp": ("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'"),
    "xfo": ("X-Frame-Options", "DENY"),
    "xcto": ("X-Content-Type-Options", "nosniff"),
    "ref": ("Referrer-Policy", "strict-origin-when-cross-origin"),
    "perm": ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
}
DJANGO_SETTINGS = {
    "hsts": "# settings.py\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True",
    "xfo": '# settings.py (keep XFrameOptionsMiddleware in MIDDLEWARE)\nX_FRAME_OPTIONS = "DENY"',
    "xcto": "# settings.py\nSECURE_CONTENT_TYPE_NOSNIFF = True",
    "ref": '# settings.py\nSECURE_REFERRER_POLICY = "strict-origin-when-cross-origin"',
}


def _header_fix(check_id: str, host: str) -> dict:
    name, value = HEADER_VALUES[check_id]
    django_code = DJANGO_SETTINGS.get(check_id) or (
        '# settings.py: add "myapp.middleware.SecurityHeadersMiddleware" to MIDDLEWARE\n'
        "# myapp/middleware.py\n"
        "class SecurityHeadersMiddleware:\n"
        "    def __init__(self, get_response):\n"
        "        self.get_response = get_response\n\n"
        "    def __call__(self, request):\n"
        "        response = self.get_response(request)\n"
        f'        response["{name}"] = "{value}"\n'
        "        return response"
    )
    return {
        "steps": [
            f"Add the {name} response header with the value shown in the code for your server.",
            "Start with Content-Security-Policy-Report-Only for a few days so nothing on your site breaks, then switch to the enforcing header."
            if check_id == "csp" else "Apply it to every response, not only the home page.",
            "Deploy the change.",
            "Press Re-scan and verify. This finding should move to Resolved.",
        ],
        "code": {
            "nginx": f'# inside your server {{ }} block\nadd_header {name} "{value}" always;',
            "apache": f'# run once: a2enmod headers\nHeader always set {name} "{value}"',
            "django": django_code,
            "express": "// optional: npm i helmet, which sets most of these headers for you\n"
                       f'app.use((req, res, next) => {{\n  res.setHeader("{name}", "{value}");\n  next();\n}});',
            "static": f"# Netlify: create a file named _headers in your publish folder\n/*\n  {name}: {value}\n\n"
                      f'# Vercel: vercel.json\n{{ "headers": [{{ "source": "/(.*)", "headers": [{{ "key": "{name}", "value": "{value}" }}] }}] }}',
        },
        "verify": f"curl -sI https://{host} | grep -i {name.lower()}",
    }


def fix_for(check_id: str, host: str) -> dict:
    if check_id in HEADER_VALUES:
        return _header_fix(check_id, host)
    if check_id == "cookie":
        return {
            "steps": ["Find where your app sets the session cookie (framework setting or res.cookie call).",
                      "Turn on Secure and HttpOnly, and keep SameSite at Lax or Strict.",
                      "Deploy, then log in again so a new cookie is issued.", "Press Re-scan and verify."],
            "code": {
                "nginx": "# only if your app cannot set flags itself (nginx 1.19.3+)\nproxy_cookie_flags ~ secure httponly samesite=lax;",
                "apache": "Header edit Set-Cookie ^(.*)$ $1;HttpOnly;Secure;SameSite=Lax",
                "django": '# settings.py\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nCSRF_COOKIE_SECURE = True\nSESSION_COOKIE_SAMESITE = "Lax"',
                "express": 'app.use(session({\n  secret: process.env.SESSION_SECRET,\n  cookie: { httpOnly: true, secure: true, sameSite: "lax" },\n}));',
                "static": "# Static hosts do not set session cookies.\n# Fix this in the backend or API that sets the cookie (see the Django or Express tab).",
            },
            "verify": f"curl -sI https://{host} | grep -i set-cookie",
        }
    if check_id == "redir":
        return {
            "steps": ["Redirect every http:// request to the https:// version of the same address.", "Use a permanent 301 redirect.",
                      f"Deploy, then open http://{host} in a browser to confirm it jumps to https.", "Press Re-scan and verify."],
            "code": {
                "nginx": f"server {{\n  listen 80;\n  server_name {host};\n  return 301 https://$host$request_uri;\n}}",
                "apache": "RewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                "django": '# settings.py\nSECURE_SSL_REDIRECT = True\n# behind a proxy that terminates TLS, also set:\nSECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")',
                "express": 'app.set("trust proxy", 1);\napp.use((req, res, next) => {\n  if (!req.secure) return res.redirect(301, "https://" + req.headers.host + req.url);\n  next();\n});',
                "static": "# Netlify: Domain management > HTTPS > Force HTTPS\n# Vercel: HTTP is redirected to HTTPS automatically.\n# If it still fails, check your DNS or CDN in front of the host.",
            },
            "verify": f"curl -sI http://{host} | head -n 3",
        }
    if check_id == "server":
        return {
            "steps": ["Stop the server from announcing its name and version.", "Remove X-Powered-By from your framework as well.",
                      "Deploy the change.", "Press Re-scan and verify."],
            "code": {
                "nginx": "# http { } block\nserver_tokens off;",
                "apache": "ServerTokens Prod\nServerSignature Off",
                "django": "# Django does not send a Server header itself.\n# Hide it in the web server in front (see the Nginx or Apache tab).",
                "express": 'app.disable("x-powered-by");',
                "static": "# Controlled by the hosting platform. Nothing to change here.\n# If the header shows a version, it comes from a proxy or CDN in front of the host.",
            },
            "verify": f'curl -sI https://{host} | grep -iE "^(server|x-powered-by)"',
        }
    if check_id == "cors":
        return {
            "steps": ["Replace the * wildcard with the exact origins that need access.", "Never combine a wildcard with credentials.",
                      "Deploy the change.", "Press Re-scan and verify."],
            "code": {
                "nginx": '# remove: add_header Access-Control-Allow-Origin *;\nadd_header Access-Control-Allow-Origin "https://app.example.com" always;\nadd_header Vary Origin always;',
                "apache": 'Header always set Access-Control-Allow-Origin "https://app.example.com"\nHeader always set Vary Origin',
                "django": '# pip install django-cors-headers\n# settings.py\nCORS_ALLOWED_ORIGINS = ["https://app.example.com"]\nCORS_ALLOW_CREDENTIALS = True',
                "express": '// npm i cors\napp.use(cors({ origin: ["https://app.example.com"], credentials: true }));',
                "static": '# Netlify _headers\n/api/*\n  Access-Control-Allow-Origin: https://app.example.com\n\n# Vercel vercel.json\n{ "headers": [{ "source": "/api/(.*)", "headers": [{ "key": "Access-Control-Allow-Origin", "value": "https://app.example.com" }] }] }',
            },
            "verify": f'curl -sI -H "Origin: https://evil.example" https://{host} | grep -i access-control',
        }
    if check_id == "tls":
        return {
            "steps": ["Allow only TLS 1.2 and TLS 1.3.", "Reload the web server or proxy.", "Test an old protocol: it should now fail.", "Press Re-scan and verify."],
            "code": {
                "nginx": "ssl_protocols TLSv1.2 TLSv1.3;",
                "apache": "SSLProtocol -all +TLSv1.2 +TLSv1.3",
                "django": "# TLS is configured in the web server or load balancer in front of Django.\n# See the Nginx or Apache tab.",
                "express": 'https.createServer({ minVersion: "TLSv1.2", key, cert }, app).listen(443);',
                "static": "# Netlify and Vercel already require TLS 1.2 or newer.\n# If this finding appears, a CDN or proxy in front of the site allows older versions.",
            },
            "verify": f'openssl s_client -connect {host}:443 -tls1_1 </dev/null 2>&1 | grep -i "handshake failure"',
        }
    raise KeyError(check_id)
