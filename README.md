# DeployGuard AI

Website security regression testing with AI explanations. Django + SQLite + Bootstrap 5.

A user scans a website, gets findings with evidence and a fix guide, deploys the fix and scans again. Old and new scans are compared
(new / resolved / unchanged / recurring), and a branded PDF report (logo + watermark) can be downloaded.
The admin approves accounts, sees every user's websites and AI prompts, browses the database and stores the Gemini API key.

## Run it on your computer

Needs Python 3.10 or newer.

```bash
cd deployguard
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # Windows: copy .env.example .env
# open .env and set DJANGO_SECRET_KEY to any long random string

python manage.py migrate           # creates db.sqlite3
python manage.py create_admin      # creates the admin from ADMIN_USERNAME / ADMIN_PASSWORD in .env
python manage.py seed_demo         # optional: demo users and scan history
python manage.py runserver
```

Open http://127.0.0.1:8000/

| Account | Login |
|---|---|
| Admin (goes to the admin panel) | `uzair.root` / the `ADMIN_PASSWORD` in `.env` |
| Demo developer (after `seed_demo`) | `demo.dev` / `Demo@1234` |

Run the tests: `python manage.py test`

## Multi-factor authentication (MFA)

Any authenticator app works (Google Authenticator, Microsoft Authenticator, Authy, 1Password). Open **Security** from the avatar menu,
scan the QR code, enter the 6-digit code and save the 8 one-time recovery codes.

- Sign-in becomes two steps: password, then code (or a recovery code). Codes cannot be reused; 5 wrong tries lock it for 15 minutes.
- Admins are forced to set up MFA before they can open the panel (`REQUIRE_ADMIN_MFA=1`). Set `REQUIRE_USER_MFA=1` to require it for everyone.
- The secret is stored encrypted in the database; recovery codes are stored hashed.
- Locked out? Admin panel > Users > the user > **Reset MFA**, or run `python manage.py reset_mfa <username>`.

The logo in every page links to the public Home page (`/`).

## Security notes

- Scanner requests are pinned to the IP addresses that passed the public-address check, so DNS rebinding cannot redirect a scan to an internal address.
- Rate limits and login lockouts are kept in the database (cache table `dg_cache`, created by `migrate`), so they are shared by all workers and survive restarts.

## Where the data is stored

Everything is in one SQLite file, `db.sqlite3` (change the location with `DATABASE_PATH` in `.env`).
Tables: users, profiles (approval status), websites, scans, findings, ai_prompts and app_settings.
The admin can browse them under **Database** in the panel, or in Django's own admin at `/django-admin/`.

## The Gemini API key

1. Create a free key at https://aistudio.google.com/apikey
2. Sign in as admin, open **AI key**, paste the key and save.
3. The key is encrypted (Fernet, derived from `DJANGO_SECRET_KEY`) and saved in the `app_settings` table.
   It is used on the server only. Users never see it and the browser never receives it.
4. Every prompt and answer is saved in `ai_prompts` and shown under **Prompts** and on each user's page.
   Without a key, users get a sample explanation built from the scanner's evidence.

If you change `DJANGO_SECRET_KEY` later, enter the API key again.

## Pages: one HTML file and one CSS file each

| Page | Template | Stylesheet |
|---|---|---|
| Home (public) | `templates/home.html` | `home.css` |
| Sign in | `templates/accounts/login.html` | `static/css/pages/auth.css` + `login.css` |
| Request access | `templates/accounts/register.html` | `auth.css` + `register.css` |
| MFA code | `templates/accounts/mfa_verify.html` | `auth.css` + `mfa_verify.css` |
| Security (MFA setup) | `templates/accounts/security.html` | `security.css` (+ `static/js/security.js`) |
| Dashboard | `templates/scans/dashboard.html` | `dashboard.css` |
| Scan detail | `templates/scans/scan_detail.html` | `scan_detail.css` (+ `static/js/scan_detail.js`) |
| Admin overview | `templates/panel/overview.html` | `panel_overview.css` |
| Approvals | `templates/panel/approvals.html` | `panel_approvals.css` |
| Users | `templates/panel/users.html` | `panel_users.css` |
| User detail | `templates/panel/user_detail.html` | `panel_user_detail.css` |
| AI prompts | `templates/panel/prompts.html` | `panel_prompts.css` |
| Website links | `templates/panel/links.html` | `panel_links.css` |
| Database | `templates/panel/database.html` | `panel_database.css` |
| AI key | `templates/panel/settings.html` | `panel_settings.css` |

Shared by all pages: `templates/base.html`, `static/css/base.css` (colors, fonts, buttons, effects), `static/js/base.js`, `static/js/theme.js`
and Bootstrap 5 in `static/vendor/bootstrap/`. Change colors and fonts at the top of `base.css`.

## How scanning and comparison work

- `scans/scanner.py` runs 11 checks: HSTS, CSP, clickjacking, MIME sniffing, Referrer-Policy, Permissions-Policy, cookie flags,
  HTTP to HTTPS redirect, server version disclosure, CORS and legacy TLS.
- `scans/compare.py` classifies each check against the previous scan and the site's history.
  Recurring means it was fixed earlier and has come back.
- `scans/fixes.py` holds the fix guides (steps, code for Nginx / Apache / Django / Node-Express / Netlify-Vercel, and a verify command).
- `scans/pdf.py` builds the PDF with ReportLab.
- The scanner calls only public addresses on ports 80 and 443 and re-checks every redirect, so it cannot be pointed at internal networks.
  Set `ALLOW_PRIVATE_TARGETS=1` only on your own machine to scan `localhost`.
- Users must confirm they own the site before each scan. Only test websites you own or have permission to test.

## Deploy

Netlify and Vercel host static sites only, so this Django app cannot run there. Use a Python host.

**Render (or similar)**
1. Push the folder to GitHub and create a Web Service from it.
2. Build command: `./build.sh`  Start command: `gunicorn config.wsgi`
3. Environment variables: `DJANGO_SECRET_KEY`, `DJANGO_DEBUG=0`, `DJANGO_ALLOWED_HOSTS=your-app.onrender.com`,
   `DJANGO_CSRF_TRUSTED_ORIGINS=https://your-app.onrender.com`, `ADMIN_USERNAME`, `ADMIN_PASSWORD`, `ADMIN_EMAIL`.
4. SQLite needs a persistent disk. Attach one and set `DATABASE_PATH` to a file on it, or the data resets on every deploy.

**PythonAnywhere**: upload the folder, create a virtualenv, `pip install -r requirements.txt`, create `.env`, run `migrate`, `create_admin`
and `collectstatic`, then point the web app's WSGI file at `config.wsgi` and map `/static/` to `staticfiles/`.

Before going live: use a long random `DJANGO_SECRET_KEY`, keep `DJANGO_DEBUG=0`, change the admin password, and keep `.env` out of Git.

## Known limits

- SQLite suits a course project or a small team. For many users switch `DATABASES` to PostgreSQL.
- Scans run inside the web request (5 to 20 seconds). For heavy use move them to a background worker.
- Login lockout and rate limits use Django's in-memory cache, which is per process. Use Redis or the database cache when you run several workers.
- DNS answers are checked before each request, but a hostile DNS server could still change its answer in between. Run the app without access to your internal network.
