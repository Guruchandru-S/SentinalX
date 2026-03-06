const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('../db/database');
const { v4: uuidv4 } = require('uuid');
const { OAuth2Client } = require('google-auth-library');

const JWT_SECRET = process.env.JWT_SECRET || 'aegis-secret-key-change-in-production';
const JWT_EXPIRES = '8h';

const GOOGLE_CLIENT_ID = '341392170764-aaqqfj4ro17vge5k3t00c8hfe67u7g38.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

function signToken(user) {
    return jwt.sign(
        { id: user.id || user.email, email: user.email, name: user.name, role: user.role },
        JWT_SECRET, { expiresIn: JWT_EXPIRES }
    );
}

router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });
    const user = db.get('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email]);
    if (!user) return res.status(401).json({ error: 'Invalid credentials.' });
    if (password && user.password_hash) {
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const token = signToken(user);
    res.json({
        success: true, token,
        user: { id: user.id, email: user.email, name: user.name, role: user.role },
        expiresIn: JWT_EXPIRES,
        message: 'Authentication successful. Welcome to AEGIS Command Center.'
    });
});

router.post('/google', async (req, res) => {
    const { credential } = req.body;
    if (!credential) return res.status(400).json({ error: 'Google credential token is required.' });

    try {

        const ticket = await googleClient.verifyIdToken({
            idToken: credential,
            audience: GOOGLE_CLIENT_ID
        });

        const payload = ticket.getPayload();
        const { email, name, picture } = payload;

        let user = db.get('SELECT * FROM users WHERE LOWER(email) = LOWER(?)', [email]);

        if (!user) {

            const newId = `g-${uuidv4()}`;
            db.run(`INSERT INTO users (id, email, name, role, avatar_url) VALUES (?, ?, ?, ?, ?)`,
                [newId, email, name, 'analyst', picture]);
            user = { id: newId, email, name, role: 'analyst', avatar_url: picture };
        }

        const token = signToken(user);
        res.json({
            success: true, token,
            user: {
                id: user.id,
                email: user.email,
                name: user.name,
                role: user.role,
                avatar: user.avatar_url || picture
            },
            expiresIn: JWT_EXPIRES,
            message: 'Google SSO authentication successful.'
        });

    } catch (err) {
        console.error('[AUTH] Google verification failed:', err.message);
        res.status(403).json({ error: 'Invalid Google token.' });
    }
});

router.post('/logout', (req, res) => {
    res.json({ success: true, message: 'Logged out successfully.' });
});

router.get('/me', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Not authenticated.' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = db.get('SELECT id, email, name, role, avatar_url, created_at FROM users WHERE LOWER(email) = LOWER(?)', [decoded.email]);
        if (user) {
            user.avatar = user.avatar_url;
            delete user.avatar_url;
        }
        res.json({ user: user || decoded });
    } catch { res.status(403).json({ error: 'Invalid token.' }); }
});

router.post('/refresh', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided.' });
    try {
        const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
        const newToken = jwt.sign(
            { id: decoded.id, email: decoded.email, name: decoded.name, role: decoded.role },
            JWT_SECRET, { expiresIn: JWT_EXPIRES }
        );
        res.json({ token: newToken, expiresIn: JWT_EXPIRES });
    } catch { res.status(403).json({ error: 'Invalid token.' }); }
});

module.exports = router;