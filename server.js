require('dotenv').config();
const express = require('express');
const cookieSession = require('cookie-session');
const cookieParser = require('cookie-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const fsSync = require('fs');

const {
    SESSION_SECRET = '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c',
    MAGIC_LINK_SECRET = '2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c',
    EMAIL_HOST = '',
    EMAIL_PORT = 25,
    EMAIL_USER = '',
    EMAIL_PASS = '',
    EMAIL_API_KEY = '',
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
    APP_NAME = 'Static Website with Magic Link Auth App',
    APP_BASE_URL = 'http://localhost:3000',
    NODE_ENV = 'development',
    SESSION_HOURS = 24,
    ALLOWED_EMAILS_FILE = 'allowed_emails.txt',
    PORT = 3000,
} = process.env;

// Helper functions - Error handling
function fatalError(message) {
    console.error(message);
    process.exit(1);
}

// Helper functions - Configuration validation
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

    // Validate APP_BASE_URL
    try {
        new URL(APP_BASE_URL);
    } catch (error) {
        fatalError('APP_BASE_URL must be a valid URL');
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
        sessionDuration: sessionDuration * 60 * 60 * 1000, // Convert hours to milliseconds
        emailPort,
        isProduction: NODE_ENV === 'production',
        hasEmailAuth: Boolean(EMAIL_USER && (EMAIL_PASS || EMAIL_API_KEY))
    };
}

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

// Helper functions - Email validation
function isValidEmail(email) {
    return EMAIL_REGEX.test(email);
}

// Helper functions - Template processing
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

// Helper functions - Email file management
let allowedEmails = new Set();

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

function isEmailAllowed(email) {
    return allowedEmails.has(email.toLowerCase());
}

// Helper functions - Token management
function generateToken() {
    const payload = {
        expires: Date.now() + MAGIC_LINK_EXPIRY
    };

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(MAGIC_LINK_SECRET, 'hex'), iv);
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();

    return `${iv.toString('hex')}:${encrypted}:${authTag.toString('hex')}`;
}

function decryptToken(token) {
    try {
        const [ivHex, encrypted, authTagHex] = token.split(':');

        if (!ivHex || !encrypted || !authTagHex) {
            throw new Error('Invalid token format');
        }

        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');

        const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(MAGIC_LINK_SECRET, 'hex'), iv);
        decipher.setAuthTag(authTag);

        let decrypted = decipher.update(encrypted, 'hex', 'utf8');
        decrypted += decipher.final('utf8');

        const payload = JSON.parse(decrypted);

        if (!payload.expires || typeof payload.expires !== 'number') {
            throw new Error('Invalid token payload');
        }

        return payload;
    } catch (error) {
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

// Helper functions - Email sending
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

        if (NODE_ENV === 'development') {
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
            console.error('Error: No mail server configured. Set EMAIL_HOST and EMAIL_PORT environment variables.');
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

// Helper functions - Server management
function shutdown() {
    console.log('Shutting down gracefully...');
    if (server) {
        server.close((err) => {
            if (err) {
                console.error('Error closing server:', err);
                process.exit(1);
            }
            setTimeout(() => {
                console.error('Server close timeout - forcing exit');
                process.exit(1);
            }, 10000); // 10 second timeout
            console.log('Server closed');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
}

const app = express();

// Middleware
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({
    name: 'session',
    keys: [SESSION_SECRET],
    maxAge: sessionDuration,
    secure: isProduction && APP_BASE_URL.startsWith('https://'),
    httpOnly: true
}));

// Watch for changes to the allowed emails file
fsSync.watch(ALLOWED_EMAILS_FILE, async (eventType) => {
    if (eventType === 'change') {
        await loadAllowedEmails();
    }
});

// Middleware
function requireAuth(req, res, next) {
    // Check if session exists and has the expected structure
    if (req.session && typeof req.session.authenticated === 'boolean' && req.session.authenticated) {
        // Only update the session if it's below half of its total duration
        if (!req.session.expires || Date.now() > req.session.expires - (sessionDuration / 2)) {
            req.session.expires = Date.now() + sessionDuration;
        }
        next();
    } else {
        // Clear any invalid session data
        req.session = null;
        res.redirect('/auth/login');
    }
}

// Routes
app.use('/auth', express.static(path.join(__dirname, 'auth')));

app.get('/auth/login', (req, res) => {
    if (req.session.authenticated) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'auth', 'login.html'));
});

app.post('/auth/login', async (req, res) => {
    const { email } = req.body;

    if (!email || !email.includes('@')) {
        return res.redirect('/auth/login?error=Invalid email format');
    }

    try {
        // Add random delay between 0.5 and 1.5 seconds to prevent timing attacks
        const delay = Math.random() * 1000 + 500;
        await new Promise(resolve => setTimeout(resolve, delay));

        const isAllowed = await isEmailAllowed(email);
        if (isAllowed) {
            try {
                const token = generateToken();
                const verificationUrl = `${APP_BASE_URL}/auth/verify?token=${token}`;
                await sendMagicLinkEmail(email, verificationUrl);
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
        console.error('Login error:', error);
        res.redirect('/auth/login?error=An error occurred. Please try again later.');
    }
});

app.get('/auth/verify', async (req, res) => {
    const { token } = req.query;

    if (!token) {
        return res.status(400).send('Invalid verification link');
    }

    try {
        const payload = decryptToken(token);

        if (Date.now() > payload.expires) {
            return res.status(400).send('Verification link has expired');
        }

        // The token is valid, create a session
        req.session.authenticated = true;
        res.redirect('/');
    } catch (error) {
        console.error('Verification error:', error);
        // Return different error messages based on the specific error
        if (error.message === 'Invalid token format') {
            return res.status(400).send('Invalid verification link format');
        }
        if (error.message === 'Invalid token payload') {
            return res.status(400).send('Invalid verification link data');
        }
        if (error.message === 'Invalid token') {
            return res.status(400).send('Invalid verification link');
        }
        if (error.message === 'Failed to decrypt token') {
            return res.status(400).send('Could not verify the link');
        }
        return res.status(400).send('Invalid verification link');
    }
});

app.post('/auth/logout', (req, res) => {
    req.session = null;
    res.redirect('/auth/login');
});

// Protected static files
app.use('/', requireAuth, express.static(path.join(__dirname, 'public')));

// Error handling
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Server instance variable used for graceful shutdown
let server;

// Load initial allowed emails and start server
loadAllowedEmails().then(() => {
    server = app.listen(PORT, () => {
        console.log(`Server running on port ${PORT}`);
    });
});

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);