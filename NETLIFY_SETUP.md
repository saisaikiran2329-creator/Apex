# Netlify deployment

Deploy this project from a connected Git repository or with the Netlify CLI so Netlify builds and deploys the functions in `netlify/functions`. A static drag-and-drop deploy does not deploy these functions.

In the Netlify site settings, add these environment variables for the Functions runtime:

- `LOGIN_EMAIL` — the login account email.
- `LOGIN_PASSWORD` — the login account password.
- `SESSION_SECRET` — a unique, randomly generated secret. Generate one locally with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.

Keep these values in Netlify's environment-variable settings; do not put them in HTML, JavaScript, or committed files. Redeploy after setting or changing them.

The site routes `/api/login`, `/api/session`, and `/api/jobs` to Netlify Functions. Published jobs are stored in Netlify Blobs, using `jobs.json` as the initial job list.
