/**
 * Express Authentication Router — NetShield AI.
 *
 * Provides endpoints for user registration, login, user profile lookup,
 * JWT authentication, and agent API key generation.
 *
 * @module routes/auth
 */

import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'netshield_ai_secure_jwt_secret_key_2026';

/**
 * Generate a random, cryptographically secure API key string.
 * Format: ns_live_<32_hex_chars>
 */
function generateApiKey() {
  return `ns_live_${crypto.randomBytes(16).toString('hex')}`;
}

/**
 * Middleware: Verify JWT Bearer Token in Authorization header.
 */
export function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, payload) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session token' });
    }
    req.user = payload;
    next();
  });
}

// ── POST /api/auth/register ─────────────────────────────────────
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required.' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters long.' });
    }

    const db = req.app.get('db');

    // Check if user already exists
    const existingUser = db.findUserByUsernameOrEmail(email) || db.findUserByUsernameOrEmail(username);
    if (existingUser) {
      if (existingUser.email.toLowerCase() === email.toLowerCase()) {
        return res.status(409).json({ error: 'An account with this email already exists.' });
      }
      return res.status(409).json({ error: 'Username is already taken.' });
    }

    // Hash password & generate API key
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);
    const apiKey = generateApiKey();

    const newUser = db.createUser({
      username,
      email,
      passwordHash,
      apiKey,
    });

    // Create JWT token
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Account created successfully',
      token,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        apiKey: newUser.api_key,
        createdAt: newUser.created_at,
      },
    });
  } catch (err) {
    console.error('[Auth] Registration error:', err);
    res.status(500).json({ error: 'Failed to create user account.' });
  }
});

// ── POST /api/auth/login ────────────────────────────────────────
router.post('/login', async (req, res) => {
  try {
    const { identifier, password } = req.body; // identifier = email or username

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Please enter your username/email and password.' });
    }

    const db = req.app.get('db');
    const user = db.findUserByUsernameOrEmail(identifier);

    if (!user) {
      return res.status(401).json({ error: 'Invalid email/username or password.' });
    }

    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email/username or password.' });
    }

    // Update last login
    db.updateLastLogin(user.id);

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        apiKey: user.api_key,
        createdAt: user.created_at,
        lastLogin: Date.now(),
      },
    });
  } catch (err) {
    console.error('[Auth] Login error:', err);
    res.status(500).json({ error: 'Authentication failed.' });
  }
});

// ── GET /api/auth/me ────────────────────────────────────────────
router.get('/me', authenticateToken, (req, res) => {
  try {
    const db = req.app.get('db');
    const user = db.findUserById(req.user.id);

    if (!user) {
      return res.status(404).json({ error: 'User account not found.' });
    }

    res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        apiKey: user.api_key,
        createdAt: user.created_at,
        lastLogin: user.last_login,
      },
    });
  } catch (err) {
    console.error('[Auth] Fetch user profile error:', err);
    res.status(500).json({ error: 'Failed to fetch user profile.' });
  }
});

// ── POST /api/auth/regenerate-api-key ──────────────────────────
router.post('/regenerate-api-key', authenticateToken, (req, res) => {
  try {
    const db = req.app.get('db');
    const newApiKey = generateApiKey();
    const updatedUser = db.updateApiKey(req.user.id, newApiKey);

    res.json({
      message: 'API Key regenerated successfully',
      apiKey: updatedUser.api_key,
    });
  } catch (err) {
    console.error('[Auth] Regenerate API key error:', err);
    res.status(500).json({ error: 'Failed to regenerate API key.' });
  }
});

export default router;
