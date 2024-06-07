import express from "express";
import fs from "fs";
import jwt from "jsonwebtoken";
import cors from "cors";
import bcrypt from "bcrypt";
import { getFirestore } from "firebase-admin/firestore";
import { initializeApp, cert } from "firebase-admin/app";
import dotenv from 'dotenv';
import { customAlphabet } from 'nanoid';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { body, validationResult } from 'express-validator';

dotenv.config();

const serviceAccountPath = process.env.SERVICE_ACCOUNT_PATH;
const privateKeyPath = process.env.PRIVATE_KEY_PATH;
const publicKeyPath = process.env.PUBLIC_KEY_PATH;

// Debug logging
console.log('SERVICE_ACCOUNT_PATH:', serviceAccountPath);
console.log('PRIVATE_KEY_PATH:', privateKeyPath);
console.log('PUBLIC_KEY_PATH:', publicKeyPath);

if (!serviceAccountPath || !privateKeyPath || !publicKeyPath) {
    console.error('Error: Missing required environment variables');
    process.exit(1);
}

const serviceAccount = JSON.parse(fs.readFileSync(serviceAccountPath, 'utf8'));

initializeApp({
    credential: cert(serviceAccount),
});

const server = express();
const port = process.env.PORT || 8080;

const privateKey = fs.readFileSync(privateKeyPath, 'utf8');
const publicKey = fs.readFileSync(publicKeyPath, 'utf8');

server.use(express.json());
server.use(cors());
server.use(helmet());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
server.use(limiter);

// Generate a short unique user ID
const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', 10);

// User management functions
async function storeUserInFirestore(email, username, password) {
    const db = getFirestore();
    const userId = `user-${nanoid()}`;
    const userRef = db.collection("users").doc(email);
    try {
        await userRef.set({
            userId,
            username,
            email,
            password,
        });
        console.log("User successfully added");
    } catch (error) {
        console.error("Error adding user", error);
    }
}

async function getUserInFirestore(email) {
    const db = getFirestore();
    return await db.collection("users").doc(email).get();
}

async function getUserByField(field, value) {
    const db = getFirestore();
    const usersSnapshot = await db.collection("users").where(field, "==", value).get();
    return !usersSnapshot.empty;
}

async function updateUserProfile(email, updatedFields) {
    const db = getFirestore();
    const userRef = db.collection("users").doc(email);

    try {
        await userRef.update(updatedFields);
        console.log("User profile successfully updated!");
    } catch (error) {
        console.error("Error updating user profile:", error);
    }
}

// Token management functions
async function blacklistToken(token) {
    const db = getFirestore();
    await db.collection("blacklistedTokens").doc(token).set({ invalidatedAt: new Date() });
}

async function isTokenBlacklisted(token) {
    const db = getFirestore();
    const doc = await db.collection("blacklistedTokens").doc(token).get();
    return doc.exists;
}

async function authenticateToken(request, response, next) {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return response.status(401).json({ status: 'error', message: 'Access token is missing' });
    }
    if (await isTokenBlacklisted(token)) {
        return response.status(403).json({ status: 'error', message: 'Token is blacklisted' });
    }

    jwt.verify(token, publicKey, (error, user) => {
        if (error) {
            return response.status(403).json({ status: 'error', message: 'Invalid token' });
        }
        request.user = user;
        next();
    });
}

// JWT functions
function createJWT(data) {
    return jwt.sign(data, privateKey, { algorithm: "RS256", expiresIn: '1h' });
}

const ALLOWED_DOMAIN = 'gmail.com';

// User registration and login
server.post("/register", [
    body('email').isEmail().normalizeEmail(),
    body('username').trim().escape(),
    body('password').isLength({ min: 8 }).matches(/^(?=.*[A-Z])(?=.*\d)/),
    body('confirmPassword').custom((value, { req }) => value === req.body.password)
], async (request, response) => {
    const errors = validationResult(request);
    if (!errors.isEmpty()) {
        return response.status(400).json({ errors: errors.array() });
    }

    const { email, username, password, confirmPassword } = request.body;

    const emailDomain = email.split('@')[1];
    if (emailDomain !== ALLOWED_DOMAIN) {
        return response.status(403).json({ status: 'error', message: 'Email domain not allowed' });
    }

    if (password !== confirmPassword) {
        return response.status(400).json({ status: 'error', message: 'Passwords do not match' });
    }

    try {
        const emailExists = await getUserInFirestore(email);
        if (emailExists.exists) {
            return response.status(400).json({ status: 'error', message: 'Email already exists' });
        }

        const usernameExists = await getUserByField('username', username);
        if (usernameExists) {
            return response.status(400).json({ status: 'error', message: 'Username already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const passwordExists = await getUserByField('password', hashedPassword);
        if (passwordExists) {
            return response.status(400).json({ status: 'error', message: 'Password already exists' });
        }

        await storeUserInFirestore(email, username, hashedPassword);
        response.status(200).json({ status: 'ok', message: 'User Created Successfully' });
    } catch (error) {
        response.status(500).json({ status: "Error", message: error.message });
    }
});

server.post("/login", async (request, response) => {
    const { email, password } = request.body;

    const emailDomain = email.split('@')[1];
    if (emailDomain !== ALLOWED_DOMAIN) {
        return response.status(403).json({ status: 'error', message: 'Email domain not allowed' });
    }

    try {
        const user = await getUserInFirestore(email);

        if (user.exists && await bcrypt.compare(password, user.get("password"))) {
            const token = createJWT({ email, userId: user.get("userId") });
            response.status(200).json({
                status: "Successfully Login",
                loginResult: {
                    userId: user.get("userId"),
                    name: user.get("username"),
                    token: token
                }
            });
        } else {
            response.status(403).json({ status: "error", message: "Invalid email or password" });
        }
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

server.post("/logout", authenticateToken, async (request, response) => {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
        await blacklistToken(token);
    }
    response.status(200).json({ status: 'ok', message: 'Logged out successfully' });
});

// Profile management
server.put('/profile', authenticateToken, async (request, response) => {
    const email = request.user.email;
    const { fullname, username } = request.body;
    const updatedFields = {};

    if (fullname) updatedFields.fullname = fullname;
    if (username) updatedFields.username = username;

    try {
        await updateUserProfile(email, updatedFields);
        response.status(200).json({ status: 'ok', message: 'User profile updated successfully' });
    } catch (error) {
        console.error("Error updating user profile:", error);
        response.status(500).json({ status: 'error', message: 'Error updating user profile' });
    }
});

// Forum management

// Get discussions
server.get("/forum", async (request, response) => {
    const db = getFirestore();

    try {
        const discussionsSnapshot = await db.collection("discussions").get();
        const discussions = discussionsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // Sort discussions by the number of comments
        discussions.sort((a, b) => (b.comments ? b.comments.length : 0) - (a.comments ? a.comments.length : 0));

        response.status(200).json({ status: 'ok', discussions });
    } catch (error) {
        console.error("Error fetching discussions:", error);
        response.status(500).json({ status: 'error', message: 'Error fetching discussions' });
    }
});

// Create a new discussion
server.post("/forum", authenticateToken, async (request, response) => {
    const { title, content } = request.body;
    const email = request.user.email;
    const db = getFirestore();

    try {
        const discussionRef = await db.collection("discussions").add({
            title,
            content,
            email,
            comments: [],
            createdAt: new Date()
        });

        response.status(201).json({ status: 'ok', message: 'Discussion created', discussionId: discussionRef.id });
    } catch (error) {
        console.error("Error creating discussion:", error);
        response.status(500).json({ status: 'error', message: 'Error creating discussion' });
    }
});

// Add a comment to a discussion
server.post("/forum/:discussionId/comments", authenticateToken, async (request, response) => {
    const { discussionId } = request.params;
    const { comment } = request.body;
    const email = request.user.email;
    const db = getFirestore();

    try {
        const discussionRef = db.collection("discussions").doc(discussionId);
        const discussionDoc = await discussionRef.get();

        if (!discussionDoc.exists) {
            return response.status(404).json({ status: 'error', message: 'Discussion not found' });
        }

        const discussion = discussionDoc.data();
        discussion.comments.push({ email, comment, createdAt: new Date() });

        await discussionRef.update({ comments: discussion.comments });

        response.status(201).json({ status: 'ok', message: 'Comment added' });
    } catch (error) {
        console.error("Error adding comment:", error);
        response.status(500).json({ status: 'error', message: 'Error adding comment' });
    }
});

// Protected route example
server.get('/protected-route', authenticateToken, (request, response) => {
    response.json({ status: 'ok', message: 'This is a protected route' });
});

server.listen(port, () => {
    console.log(`App is running on port ${port}`);
});
