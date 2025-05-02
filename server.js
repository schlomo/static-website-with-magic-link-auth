// Load environment variables from .env file
const envFile = process.env.NODE_ENV_FILE || '.env';
require('dotenv').config({ path: envFile });
// Import required modules
const express = require('express');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const morgan = require('morgan');
const { createHttpTerminator } = require('http-terminator');
// Import fs modules for file system operations
const fs = require('fs').promises;
const path = require('path');
const fsSync = require('fs');

// Destructure environment variables, providing default values
const {
    // Session configuration
    SESSION_SECRET = '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c',
    MAGIC_LINK_SECRET = '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c',
    EMAIL_HOST = '',
    EMAIL_PORT = 25,
    EMAIL_USER = '',
    EMAIL_PASS = '',
    EMAIL_API_KEY = '',
    // Email default values
    EMAIL_FROM = '"Magic Link Auth" <noreply@localhost>',
    EMAIL_SUBJECT = 'Your Magic Link',
    EMAIL_TEXT_TEMPLATE = 'Click this link to sign in: {url}',
    EMAIL_HTML_TEMPLATE = `
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2>Sign In to {appName}</h2>
            <p>Click the button below to sign in to your account:</p>
            <a href="{url}" 
               style="display: inline-block; padding: 10px 20px; background-color: #4CAF50; color: white; text-decoration: none; border-radius: 5px;">
                Sign In
            </a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">{url}</p>
            <p>This link will expire in {expiryMinutes} minutes.</p>
        </body>
        </html>
    `,
    // Application default values
    APP_NAME = 'Static Website with Magic Link Auth App',
    APP_BASE_URL,
    NODE_ENV = 'development',
    SESSION_HOURS = 24,
    ALLOWED_EMAILS_FILE = 'allowed_emails.txt',
    PORT = 3000,
    // Get the variable from the env
} = process.env;

// Debug mode configuration
const DEBUG = process.env.DEBUG !== undefined;
if (DEBUG) {
    console.log('Debug mode is enabled');
}

// Trace mode configuration
const TRACE = process.env.TRACE !== undefined;
if (TRACE) {
    console.log('Trace mode is enabled');
    // Helper function to format headers for tracing
    const formatHeaders = (headers) => JSON.stringify(Object.fromEntries(Object.entries(headers).sort()), null, 2);

    // Custom trace format with full headers
    morgan.token('req-headers', (req) => formatHeaders(req.headers));
    morgan.token('res-headers', (req, res) => formatHeaders(res.getHeaders()));
}

/**
 * @function debug - Logs debug information if DEBUG environment variable is set.
 * @param {string} message - The debug message to log.
 * @param {any} [data] - Optional data to log.
 */
function debug(message, data) {
    if (DEBUG) {
        console.log(`[DEBUG] ${message}${data !== undefined ? ' ' + JSON.stringify(data) : ''}`);
    }
}

// Helper function - Error handling
/**
 * @function fatalError - Logs an error message and exits the process with a failure code.
 * @param {string} message - The error message to log.
 */
function fatalError(message) {
    console.error(message);
    process.exit(1);
}

/** @function validateConfig - Validates the application's configuration. */
function validateConfig() {
    // Validate SESSION_HOURS
    const sessionDuration = Number.parseFloat(SESSION_HOURS);
    if (isNaN(sessionDuration) || sessionDuration <= 0) {
        fatalError('SESSION_HOURS must be a positive number (in hours)');
    }

    // Validate EMAIL_PORT
    const emailPort = parseInt(EMAIL_PORT, 10);
    if (isNaN(emailPort) || emailPort < 1 || emailPort > 65535) {
        fatalError('EMAIL_PORT must be a valid port number (1-65535)');
    }

    // Validate NODE_ENV
    if (!['development', 'production'].includes(NODE_ENV)) {
        fatalError('NODE_ENV must be either "development" or "production"');
    }

    if (APP_BASE_URL) {
        // Validate APP_BASE_URL
        try {
            new URL(APP_BASE_URL);
        } catch (error) {
            fatalError('APP_BASE_URL must be a valid URL');
        }
    } else {
        console.warn('Notice: APP_BASE_URL is not set. It will be dynamically determined at runtime.');
    }

    // Validate secrets format
    if (!/^[0-9a-f]{64}$/i.test(SESSION_SECRET)) {
        fatalError('SESSION_SECRET must be a 32-byte hex string (64 characters) for AES-256 encryption');
    }
    if (!/^[0-9a-f]{64}$/i.test(MAGIC_LINK_SECRET)) {
        fatalError('MAGIC_LINK_SECRET must be a 32-byte hex string (64 characters) for AES-256 encryption');
    }

    // Validate email configuration
    if (!EMAIL_USER && !EMAIL_API_KEY) {
        console.warn('Warning: Neither EMAIL_USER nor EMAIL_API_KEY is set. Email sending may not work.');
    }

    return {
        // Convert hours to milliseconds
        sessionDuration: sessionDuration * 60 * 60 * 1000,
        emailPort,
        isProduction: NODE_ENV === 'production',
        hasEmailAuth: Boolean(EMAIL_USER && (EMAIL_PASS || EMAIL_API_KEY))
    };
}

// Main part of the code
// This is the part that validate the environment variables
// and prepare the server configuration.


// Validate configuration and get derived values
const { sessionDuration, emailPort, isProduction, hasEmailAuth } = validateConfig();

// Helper function to mask secrets for logging
function maskSecret(secret) {
    if (!secret) return 'not set';
    return `${secret.slice(0, 3)}...${secret.slice(-3)}`;
}

// Log all configuration on startup
console.log(`
Server Configuration:
-------------------
Environment Variables:
-------------------
NODE_ENV: ${NODE_ENV}
PORT: ${PORT}
APP_NAME: ${APP_NAME}
APP_BASE_URL: ${APP_BASE_URL}
SESSION_HOURS: ${SESSION_HOURS}
SESSION_SECRET: ${maskSecret(SESSION_SECRET)}
MAGIC_LINK_SECRET: ${maskSecret(MAGIC_LINK_SECRET)}
EMAIL_HOST: ${EMAIL_HOST}
EMAIL_PORT: ${EMAIL_PORT}
EMAIL_USER: ${maskSecret(EMAIL_USER)}
EMAIL_PASS: ${maskSecret(EMAIL_PASS)}
EMAIL_API_KEY: ${maskSecret(EMAIL_API_KEY)}
EMAIL_FROM: ${EMAIL_FROM}
EMAIL_SUBJECT: ${EMAIL_SUBJECT}
EMAIL_TEXT_TEMPLATE: ${EMAIL_TEXT_TEMPLATE}
EMAIL_HTML_TEMPLATE: ${EMAIL_HTML_TEMPLATE.length} characters
ALLOWED_EMAILS_FILE: ${ALLOWED_EMAILS_FILE}
-------------------
Derived Configuration:
-------------------
Session Duration (ms): ${sessionDuration}
Email Port: ${emailPort}
Is Production: ${isProduction}
Has Email Auth: ${hasEmailAuth}
-------------------
`);

// Constants
const MAGIC_LINK_EXPIRY = 15 * 60 * 1000; // 15 minutes
const EMAIL_REGEX = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

/**
 * @function isValidEmail - Checks if an email is in a valid format.
 * @param {string} email - The email to validate.
 * @returns {boolean} - True if the email is valid, false otherwise.
 */
function isValidEmail(email) {
    return EMAIL_REGEX.test(email);
}

/**
 * @function processTemplate - Processes a template string, replacing variables with provided values.
 * @param {string} template - The template string.
 * @param {object} variables - An object with key-value pairs to replace in the template.
 * @returns {string} - The processed template.
 */
function processTemplate(template, variables) {
    return template.replace(/\{(\w+)\}/g, (match, key) => {
        if (key in variables) {
            return variables[key];
        }
        // Log a warning when a template variable is missing to help debug template issues
        console.warn(`Warning: Unknown template variable {${key}}`);
        return match;
    });
}

// Variables
// Set that contains the allowed emails
let allowedEmails = new Set();

/**
 * @function loadAllowedEmails - Loads allowed emails from the file specified by ALLOWED_EMAILS_FILE.
 *
 * This function reads a file that should contain one allowed email per line.
 * It validates each email format and stores them in the allowedEmails Set.
 */

async function loadAllowedEmails() {
    try {
        const content = await fs.readFile(ALLOWED_EMAILS_FILE, 'utf-8');
        const emails = content
            .split('\n')
            .map(line => line.trim())
            .filter(line => line && !line.startsWith('#'))
            .map(email => email.toLowerCase());

        // Validate all emails
        const invalidEmails = emails.filter(email => !isValidEmail(email));
        if (invalidEmails.length > 0) {
            fatalError(`Error: Invalid email format(s) in allowed emails file: ${invalidEmails.join(', ')}\n` +
                `File: ${ALLOWED_EMAILS_FILE}\n` +
                `Please fix the email format(s) and try again.`);
        }

        allowedEmails = new Set(emails);
        console.log(`Loaded ${allowedEmails.size} allowed email(s) from ${ALLOWED_EMAILS_FILE}`);
    } catch (error) {
        if (error.code === 'ENOENT') {
            fatalError(`Error: Allowed emails file not found at ${ALLOWED_EMAILS_FILE}\n` +
                `Please create the file with one email address per line.\n` +
                `Lines starting with # are comments and will be ignored.`);
        } else if (error.code === 'EACCES') {
            fatalError(`Error: Permission denied reading allowed emails file at ${ALLOWED_EMAILS_FILE}\n` +
                `Please check file permissions and ensure the application can read the file.`);
        } else if (error.code === 'EISDIR') {
            fatalError(`Error: ${ALLOWED_EMAILS_FILE} is a directory, not a file\n` +
                `Please ensure the path points to a file containing allowed email addresses.`);
        } else {
            fatalError(`Error loading allowed emails file: ${error.message}\n` +
                `File: ${ALLOWED_EMAILS_FILE}\n` +
                `Please check the file exists and is readable.`);
        }
    }
}

/**
 * @function isEmailAllowed - Checks if an email is in the allowedEmails set.
 * @param {string} email - The email to check.
 * @returns {boolean} - True if the email is allowed, false otherwise.
 */
function isEmailAllowed(email) {
    return allowedEmails.has(email.toLowerCase());
}

/**
 * @function generateToken - Generates an encrypted token with an expiration time.
 *
 * This function creates a token that includes an expiration date,
 * encrypts it using AES-256-GCM, and formats it for use in a URL.
 * @returns {string} - The generated token.
 */
function generateToken() {
    const payload = {
        expires: Date.now() + MAGIC_LINK_EXPIRY
    };

    debug('Generating token with payload:', payload);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(MAGIC_LINK_SECRET, 'hex'), iv);
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    const token = `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
    debug('Generated token:', token);
    return token;
}

/**
 * @function decryptToken - Decrypts and validates a token.
 *
 * This function takes an encrypted token, decrypts it, and checks
 * if the token has expired.
 * @param {string} token - The token to decrypt.
 */
function decryptToken(token) {
    try {
        debug('Decrypting token:', token);
        const [ivHex, encrypted, authTagHex] = token.split(':');

        if (!ivHex || !encrypted || !authTagHex) {
            debug('Invalid token format - missing components');
            throw new Error('Invalid token format');
        }

        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(MAGIC_LINK_SECRET, 'hex'), iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const payload = JSON.parse(decrypted);
        debug('Decrypted token payload:', payload);

        if (!payload.expires || typeof payload.expires !== 'number') {
            debug('Invalid token payload - missing or invalid expires field');
            throw new Error('Invalid token payload');
        }

        return payload;
    } catch (error) {
        debug('Token decryption error:', error.message);
        if (error.message === 'Invalid token format') {
            throw error;
        }
        if (error.message === 'Invalid token payload') {
            throw error;
        }
        if (error.message.includes('bad decrypt')) {
            throw new Error('Invalid token');
        }
        throw new Error('Failed to decrypt token');
    }
}

// Email transporter setup
const transporter = nodemailer.createTransport({
    host: EMAIL_HOST,
    port: emailPort,
    secure: false, // We're using STARTTLS
    auth: EMAIL_API_KEY ? {
        user: EMAIL_USER || 'apikey',
        pass: EMAIL_API_KEY
    } : EMAIL_USER && EMAIL_PASS ? {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    } : false,

});

/**
 * @function sendMagicLinkEmail - Sends a magic link email.
 *
 * This function sends a magic link to the user's email address.
 * It uses the `nodemailer` library to send the email.
 * @param {string} email - The recipient's email address.
 * @param {string} verificationUrl - The magic link URL.
 * @returns {Promise<void>} - Promise that resolves when the email is sent.
 */
async function sendMagicLinkEmail(email, verificationUrl) {
    if (!EMAIL_FROM) {
        console.error('Error: No FROM address configured. Set EMAIL_FROM environment variable with format: "Display Name" <email@domain.com>');
        console.log('Email would be sent with these options:', {
            to: email,
            subject: processTemplate(EMAIL_SUBJECT, { url: verificationUrl }),
            verificationUrl: verificationUrl
        });
        return;
    }

    const templateVariables = {
        url: verificationUrl,
        appName: APP_NAME,
        expiryMinutes: Math.floor(MAGIC_LINK_EXPIRY / (60 * 1000))
    };

    const mailOptions = {
        from: EMAIL_FROM,
        to: email,
        subject: processTemplate(EMAIL_SUBJECT, templateVariables),
        text: processTemplate(EMAIL_TEXT_TEMPLATE, templateVariables),
        html: processTemplate(EMAIL_HTML_TEMPLATE, templateVariables)
    };

    try {
        const info = await transporter.sendMail(mailOptions);

        if (!isProduction) {
            console.log('Email sent:');
            console.log('From:', info.envelope.from);
            console.log('To:', info.envelope.to);
            console.log('Subject:', mailOptions.subject);
            // Only log message content if it exists (not available with direct transport)
            if (info.message) {
                console.log('Text:', info.message.text);
                console.log('HTML:', info.message.html);
            } else {
                console.log('Text:', mailOptions.text);
                // Log HTML in a way that preserves formatting
                console.log('HTML:');
                console.log(mailOptions.html);
            }
        }
    } catch (error) {
        // Check if it's a connection error (no mail server)
        if (error.message.includes('ECONNREFUSED') ||
            error.message.includes('ENOTFOUND') ||
            error.message.includes('connect')) {
            console.error('Error: No valid mail server configured. Set EMAIL_HOST and EMAIL_PORT environment variables.');
            console.error(error.message);
            console.log('Email would be sent with these options:', {
                to: mailOptions.to,
                subject: mailOptions.subject,
                verificationUrl: verificationUrl
            });
            return;
        }
        // For RFC compliance errors, show the full error message
        if (error.responseCode === 550 && error.response.includes('RFC 5322')) {
            console.error('Email rejected by server:', error.response);
            console.log('Email would be sent with these options:', {
                from: mailOptions.from,
                to: mailOptions.to,
                subject: mailOptions.subject,
                verificationUrl: verificationUrl
            });
            return;
        }
        console.error('Email sending error:', error);
        throw new Error('Failed to send magic link email');
    }
}

// Create the express application
const app = express();

// Middleware Setup
// Add request logging or tracing
if (TRACE) {
    app.use(morgan(`
:method :url :status :response-time ms
Request Headers:
:req-headers
Response Headers:
:res-headers
`));
} else {
    app.use(morgan(isProduction ? 'short' : 'dev'));
}

// Parse cookies
app.use(cookieParser());
// Parse JSON bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({
    name: 'session',
    keys: [SESSION_SECRET],
    maxAge: sessionDuration,
    secure: isProduction && APP_BASE_URL?.startsWith('https://'),
    httpOnly: true
}));

// Watch for changes to the allowed emails file
fsSync.watch(ALLOWED_EMAILS_FILE, async (eventType) => {
    // reload the file if a change is detected
    if (eventType === 'change') {
        await loadAllowedEmails();
    }
});

/**
 * @function requireAuth - Middleware to require authentication for protected routes.
 * Check if the user is authenticated.
 * If not, redirect to the login page.
 */
function requireAuth(req, res, next) {
    debug('Checking authentication status');
    debug('Session data:', req.session);

    if (req.session && typeof req.session.authenticated === 'boolean' && req.session.authenticated) {
        debug('User is authenticated');
        if (!req.session.expires || Date.now() > req.session.expires - (sessionDuration / 2)) {
            req.session.expires = Date.now() + sessionDuration;
            debug('Updating session expiration to:', req.session.expires);
        }
        next();
    } else {
        debug('User is not authenticated, redirecting to login');
        req.session = null;
        res.redirect('/auth/login');
    }
}

// Routes part of the application
// Serve static files from the 'auth' directory for /auth route
app.use('/auth', express.static(path.join(__dirname, 'auth')));

// GET route for /auth/login
// If the user is already authenticated, redirect to the home page
// If not, send the login page.
app.get('/auth/login', (req, res) => {
    if (req.session.authenticated) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'auth', 'login.html'));
});
/**
 * @function /auth/login - POST route for /auth/login.
 *
 * Handles the login form submission.
 * Steps:
 * 1. Get the email from the request body.
 * 2. Check if the email is valid.
 * 3. Add a random delay.
 */
app.post('/auth/login', async (req, res) => {
    const { email } = req.body;
    // If the email is not valid, return an error
    if (!email || !email.includes('@')) {
        return res.redirect('/auth/login?error=Invalid email format');
    }

    try {
        // Add random delay between 0.5 and 1.5 seconds to prevent timing attacks
        const delay = Math.random() * 1000 + 500;
        await new Promise(resolve => setTimeout(resolve, delay));

        // Check if the email is allowed
        const isAllowed = await isEmailAllowed(email);
        // If it is allowed, generate and send the link
        if (isAllowed) {
            try {
                // Construct the base URL dynamically if APP_BASE_URL is not set
                let baseUrl = APP_BASE_URL;
                if (!APP_BASE_URL) {
                    baseUrl = new URL(req.headers.origin);
                    console.log(`Using dynamically determined base URL: ${baseUrl}`);
                }

                const token = generateToken();
                // Ensure the URL is properly constructed without double slashes
                const verificationUrl = new URL('/auth/verify', baseUrl);
                verificationUrl.searchParams.set('token', token);
                await sendMagicLinkEmail(email, verificationUrl.toString());
                console.log(`Successfully generated and sent magic link token for ${email}`);
            } catch (error) {
                console.error(`Failed to generate/send token for ${email}:`, error);
                throw error; // Re-throw to be caught by outer try-catch
            }
        } else {
            console.log(`Login attempt rejected for unauthorized email: ${email}`);
        }
        // Always show the same message, regardless of isAllowed
        res.redirect('/auth/login?message=If your email is registered, you will receive a magic link');
    } catch (error) {
        // if an error occurs, show an error page.
        console.error('Login error:', error);
        res.redirect('/auth/login?error=An error occurred. Please try again later.');
    }
});

/**
 * @function /auth/verify - GET route for /auth/verify.
 *
 * Verify the token, and set the session if valid.
 * Steps:
 * 1. Check if the token is present in the request.
 * 2. Try to decrypt the token.
 */
app.get('/auth/verify', async (req, res) => {
    const { token } = req.query;
    debug('Verifying token from request:', token);

    if (!token) {
        debug('No token provided in request');
        return res.redirect('/auth/login?error=Invalid verification link');
    }

    try {
        const payload = decryptToken(token);
        debug('Token payload:', payload);

        if (Date.now() > payload.expires) {
            debug('Token has expired');
            return res.redirect('/auth/login?error=Your verification link has expired. Please request a new one.');
        }

        debug('Token is valid, creating session');
        req.session.authenticated = true;
        res.redirect('/');
    } catch (error) {
        debug('Verification error:', error.message);
        if (error.message === 'Invalid token format') {
            return res.redirect('/auth/login?error=Invalid verification link format');
        }
        if (error.message === 'Invalid token payload') {
            return res.redirect('/auth/login?error=Invalid verification link data');
        }
        if (error.message === 'Invalid token') {
            return res.redirect('/auth/login?error=Invalid verification link');
        }
        if (error.message === 'Failed to decrypt token') {
            return res.redirect('/auth/login?error=Could not verify the link');
        }
        return res.redirect('/auth/login?error=Invalid verification link');
    }
});

// POST route for /auth/logout
// Logout the user, and redirect to the login page
app.post('/auth/logout', (req, res) => {
    debug('Logging out user');
    debug('Previous session data:', req.session);
    req.session = null;
    res.redirect('/auth/login');
});

// Protected static files part
// Serve static files from the 'public' directory if the user is logged in
app.use('/', requireAuth, express.static(path.join(__dirname, 'public')));

// Error handling part
// Generic error handler
// Log the error and send a 500 error.
app.use((err, req, res, next) => {
    // Log the error stack
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Server instance variable used for graceful shutdown
let server;
let httpTerminator;

// Start server part
// Load initial allowed emails and then start the server.
loadAllowedEmails().then(() => {
    server = app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
    httpTerminator = createHttpTerminator({ server });
});

// process management part
// set the function to call on SIGTERM
process.on('SIGTERM', shutdown);
// set the function to call on SIGINT
process.on('SIGINT', shutdown);

/**
 * @function shutdown - Handles the server's graceful shutdown.
 *
 * This function is called when the server receives a SIGTERM or SIGINT signal.
 * It closes the server and exits the process.
 * Steps:
 * 1. Logs a message indicating that the server is shutting down.
 * 2. Uses http-terminator to gracefully close all connections.
 * 3. Exits the process.
 */
async function shutdown() {
    console.log('Shutting down gracefully...');

    if (!httpTerminator) {
        console.log('No server instance found, exiting immediately');
        process.exit(0);
        return;
    }

    // Set a flag to prevent multiple shutdown attempts
    if (shutdown.shuttingDown) {
        console.log('Shutdown already in progress');
        return;
    }
    shutdown.shuttingDown = true;

    try {
        await httpTerminator.terminate();
        console.log('Server shut down successfully');
        process.exit(0);
    } catch (err) {
        console.error('Error during shutdown:', err);
        process.exit(1);
    }
}

// Initialize the shutdown flag
shutdown.shuttingDown = false;