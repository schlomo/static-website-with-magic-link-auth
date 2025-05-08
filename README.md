# Static Website Hosting with Magic Link Email Authentication

A simple Node.js application that serves static files with magic link authentication.

This implements the ideas described in my blog post [A Login Security Architecture Without Passwords](https://schlomo.schapiro.org/2022/02/login-security-architecture-without-passwords.html).

I wanted to create a simple example that shows how to implement this security architecture.

The goal is to add a layer of security on top of an existing static website without changing the website code.

To keep things simple, I accept some security compromises:
- We use symmetric encryption for the session cookie and the magic link to avoid having to store secrets in a database.
- We don't bind the token to the browser to avoid having to store the token on the server.
- We don't use a refresh token to avoid having to store the refresh token on the server.
- The magic link expires after 15 minutes, but in that time it can be used multiple times on different devices, e.g. if somebody forwarded it to another user.

All that can be mitigated by using a database to store information about the users, their devices, and the tokens.

Please send me PRs to make this code better!

## Features
- 🔒 Magic link authentication (no passwords needed)
- 📧 Email-based login
- 🛡️ Secure session management
- 📝 Configurable email templates
- 🔄 Automatic session refresh
- 🎨 Customizable error pages
- 🔍 Debug and trace modes
- 🔐 Support for both plaintext and hashed email addresses

## Quick Start

1. Clone the repository
2. Install dependencies: `npm install`
3. Create a `.env` file (see Configuration section)
4. Create an `allowed_emails.txt` file with authorized email addresses
5. Start the server: `npm start`

## Configuration

Create a `.env` file in the root directory with the following variables:

```env
# Required
SESSION_SECRET=your-32-byte-hex-secret
MAGIC_LINK_SECRET=your-32-byte-hex-secret

# Optional
PORT=3000
NODE_ENV=development
APP_NAME="Your App Name"
APP_BASE_URL=http://localhost:3000
SESSION_HOURS=24
ALLOWED_EMAILS_FILE=allowed_emails.txt

# Email Configuration (optional)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-password
# Or use API key
EMAIL_API_KEY=your-api-key
EMAIL_FROM="Your App <noreply@example.com>"
```

### Email Configuration

You can configure email sending in two ways:

1. SMTP Server:
```env
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USER=your-email@example.com
EMAIL_PASS=your-password
```

2. API Key (e.g., for SendGrid):
```env
EMAIL_API_KEY=your-api-key
EMAIL_USER=apikey
```

### Email Templates

The application uses templates for magic link emails:
- `EMAIL_TEXT_TEMPLATE`: Plain text version
- `EMAIL_HTML_TEMPLATE`: HTML version

Templates support the following variables:
- `{url}`: The magic link URL
- `{appName}`: The application name
- `{expiryMinutes}`: Number of minutes until the link expires

### Login Page

You can customize the login page by changing the `login.html` file in the `auth` directory or by mounting another version of login page and assets at `/app/auth`.

## Allowed Emails File

Create an `allowed_emails.txt` file (or specify a different name in `ALLOWED_EMAILS_FILE`) with one email address per line. You can use either plaintext emails or SHA-256 hashes.

Example `allowed_emails.txt`:
```
# This is a comment
user@example.com # This is an inline comment
8f4e2f1b3c7d6e5a9b8c7d6e5a9b8c7d6e5a9b8c7d6e5a9b8c7d6e5a9b8c7d6e5 # This is a hashed email
```

To generate a hash for an email, you can use:
```bash
echo -n "user@example.com" | shasum -a 256
```

## Docker Deployment

Run `npm run build` to build the docker image.

Run `npm run run-example` to start the server with the example environment variables. Look at `package.json` for more options.

## Production

You can use this docker image in production to replace an existing static website hosting service. Simply set the environment variables in your production environment and mount your static files in the `public` directory. Also don't forget to set the `NODE_ENV` to `production` and to add a `allowed_emails.txt` file with your production email addresses.

## Development

### Local Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create environment files:
   - `.env` - Default environment file
   - `production.env` - Production environment
   - `staging.env` - Staging environment
   etc.

3. Start the server with a specific environment file:
   ```bash
   # Using NODE_ENV_FILE environment variable
   NODE_ENV_FILE=production.env node server.js
   ```

4. Create an `allowed_emails.txt` file with test email addresses
5. Start the server:
   ```bash
   npm run dev
   ```

### Email Testing

In development mode:
- Emails are logged to console
- Sends out emails unless EMAIL_HOST is left empty

## Security

- Session secrets must be 32-byte hex strings
- Magic links expire after 15 minutes
- Sessions expire based on SESSION_HOURS, extended after less than half the time remaining
- Non-root user in Docker
- Proper signal handling for graceful shutdown
- Support for hashed email addresses
- No password storage
- Configurable session duration
- Automatic session refresh

## File Structure

- `server.js`: Main application file
- `auth/`: Authentication-related static files
- `public/`: Protected static files (sample static website)
- `allowed_emails.txt`: List of allowed email addresses
- `example.env`: Example environment variables
- `allowed_emails_dev.txt`: List of allowed email addresses (dev)

## Docker Image

The Docker image is automatically built and published to GitHub Container Registry (ghcr.io) on every push to the main branch.

To use the image:

```bash
docker pull ghcr.io/schlomo/static-website-with-magic-link-auth:latest
```

Or in a docker-compose.yml:

```yaml
services:
  app:
    image: ghcr.io/schlomo/static-website-with-magic-link-auth:latest
    # ... rest of your configuration
```
Just make sure to provide the configuration via environment variables and to add also the file with the allowed emails. You can either mount your own path with the static website onto `/public` or set a new path via the `PUBLIC_DIR` variable. Mount the content for the authentication page onto `/auth` or set a new path via the `AUTH_DIR` variable. Use the content of the `auth` dir here for inspiration.

To build your own Docker image based on this you can create a Docker file like this one:

```Dockerfile
FROM ghcr.io/schlomo/static-website-with-magic-link-auth:latest

COPY my-website /my-website
ENV PUBLIC_DIR /my-website
COPY my-auth /my-auth
ENV AUTH_DIR /my-auth
COPY my-allowed-emails.txt /my-allowed-emails.txt
ENV ALLOWED_EMAILS_FILE /my-allowed-emails.txt
COPY my-config.env /my-config.env
ENV NODE_ENV_FILE /my-config.env
```

And of course add the remaining configuration to `my-config.env`.

## Debugging and Tracing

The application supports two modes for debugging and tracing:

### Debug Mode

Enable debug mode by setting the `DEBUG` environment variable to any value:
```bash
DEBUG=1 node server.js
```

Debug mode will output detailed information about:
- Token generation and verification
- Session management
- Authentication state changes
- Error conditions

Example debug output:
```
[DEBUG] Token generated {"expires":1234567890}
[DEBUG] Session updated {"authenticated":true,"expires":1234567890}
```

### Trace Mode

Enable trace mode by setting the `TRACE` environment variable to any value:
```bash
TRACE=1 node server.js
```

Trace mode will output detailed HTTP request and response information, including:
- Request method, URL, and status
- Response time
- Complete request and response headers (sorted alphabetically)

Example trace output:
```
GET /auth/login 200 15.123 ms
Request Headers:
{
  "accept": "text/html...",
  "cookie": "session=...",
  "host": "localhost:3000",
  "user-agent": "Mozilla/5.0..."
}
Response Headers:
{
  "content-length": "1234",
  "content-type": "text/html",
  "set-cookie": ["session=..."]
}
```

Both modes can be enabled simultaneously:
```bash
DEBUG=1 TRACE=1 node server.js
```

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.