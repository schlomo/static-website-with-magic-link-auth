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

## License

This project is licensed under the GNU General Public License v3.0 (GPLv3). See the [LICENSE](LICENSE) file for details.

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

## Features

- Static file serving with authentication
- Magic link authentication via email
- Stateless and not database required
- Configurable email settings
- Docker support and very lightweight

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SESSION_SECRET` | 32-byte hex string for session encryption | `2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c` | Yes |
| `MAGIC_LINK_SECRET` | 32-byte hex string for magic link encryption | `2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c` | Yes |
| `EMAIL_HOST` | SMTP server host | `aspmx.l.google.com` | No |
| `EMAIL_PORT` | SMTP server port | `25` | No |
| `EMAIL_USER` | SMTP username | empty | No |
| `EMAIL_PASS` | SMTP password | empty | No |
| `EMAIL_API_KEY` | Alternative to username/password | empty | No |
| `EMAIL_FROM` | Sender email address | `"Magic Link Auth <noreply@localhost>"` | No |
| `EMAIL_SUBJECT` | Subject line for magic link emails | `"Your Magic Link"` | No |
| `EMAIL_TEXT_TEMPLATE` | Plain text template for magic link emails | `"Click this link to sign in: {url}"` | No |
| `EMAIL_HTML_TEMPLATE` | HTML template for magic link emails | See server.js | No |
| `APP_NAME` | Application name for email templates | `"Static Website with Magic Link Auth App"` | No |
| `APP_BASE_URL` | Base URL for magic links | `http://localhost:3000` | No |
| `NODE_ENV` | Environment (development/production) | `development` | No |
| `SESSION_HOURS` | Session duration in hours | `24` | No |
| `ALLOWED_EMAILS_FILE` | Path to file containing allowed emails | `allowed_emails.txt` | No |
| `PORT` | Server port | `3000` | No |

### Email Configuration

The application supports two authentication methods for sending emails:
1. Username/Password authentication
2. API Key authentication

At least one of these must be configured for email functionality to work:
- Set both `EMAIL_USER` and `EMAIL_PASS` for username/password auth
- Set `EMAIL_API_KEY` for API key auth, it will use `apikey` as the username

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

## Allowed Emails

The application uses a file called `allowed_emails.txt` to determine which email addresses are allowed to log in. This file:

- Must be mounted into the container at `/app/allowed_emails.txt` (or whatever you set the `ALLOWED_EMAILS_FILE` to)
- Contains one email address per line
- Lines starting with # are comments
- Empty lines are ignored
- Is case-insensitive
- Is automatically reloaded when changed

Example format:
```
# Admin users
admin@example.com
support@example.com

# Regular users
user1@example.com
user2@example.com
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
   - etc.

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

## File Structure

- `server.js`: Main application file
- `auth/`: Authentication-related static files
- `public/`: Protected static files (sample static website)
- `allowed_emails.txt`: List of allowed email addresses
- `example.env`: Example environment variables
- `allowed_emails_dev.txt`: List of allowed email addresses (dev)

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
