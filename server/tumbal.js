import express from "express";
import fs from "fs";
import jwt from "jsonwebtoken";
import cors from "cors";
import bcrypt from "bcrypt";
import { getFirestore } from "firebase-admin/firestore";
import { initializeApp, cert } from "firebase-admin/app";
import { Storage } from '@google-cloud/storage';
import multer from 'multer';
import path from 'path';
import dotenv from 'dotenv';
import { customAlphabet } from 'nanoid';
import moment from 'moment';

dotenv.config();

const serviceAccountPath = process.env.SERVICE_ACCOUNT_PATH;
const privateKeyPath = process.env.PRIVATE_KEY_PATH;
const publicKeyPath = process.env.PUBLIC_KEY_PATH;
const bucket = new Storage().bucket(process.env.GCLOUD_STORAGE_BUCKET);

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
server.use(express.urlencoded({ extended: true }));
server.use(cors());

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

async function storeForumInFirestore(forumId, forumTitle, forumContent, userId, username) {
    const db = getFirestore();
    const forumsRef = db.collection("discussions");

    await forumsRef.doc(forumId).set({
        forumId,
        forumTitle,
        forumContent,
        userId,
        username,
        createdAt: new Date()
    });
}

async function storeCommentInFirestore(forumId, commentContent, userId, username) {
    const db = getFirestore();
    const forumRef = db.collection("discussions").doc(forumId);

    await db.runTransaction(async (transaction) => {
        const forumDoc = await transaction.get(forumRef);
        if (!forumDoc.exists) {
            throw new Error("Forum not found");
        }

        const forumData = forumDoc.data();
        const newComment = {
            commentId: `comment-${nanoid()}`,
            commentContent,
            userId,
            username,
            createdAt: new Date()
        };
        const updatedComments = [...(forumData.comments || []), newComment];
        transaction.update(forumRef, { comments: updatedComments });
    });
}

// JWT functions

function createJWT(data) {
    return jwt.sign(data, privateKey, { algorithm: "RS256" });
}

server.post("/register", async (request, response) => {
    const { email, username, password, confirmPassword } = request.body;

    const emailDomain = email.split('@')[1];
    if (emailDomain !== ALLOWED_DOMAIN) {
        return response.status(403).json({ status: 'error', message: 'Email domain not allowed' });
    }

    if (password !== confirmPassword) {
        return response.status(400).json({ status: 'error', message: 'Passwords do not match' });
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d)/;
    if (!passwordRegex.test(password)) {
        return response.status(400).json({ status: 'error', message: 'Password must contain at least one uppercase letter and one number' });
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

        const passwordExists = await getUserByField('password', await bcrypt.hash(password, 10));
        if (passwordExists) {
            return response.status(400).json({ status: 'error', message: 'Password already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
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
            const token = createJWT({ email, userId: user.get("userId"), username: user.get("username") });
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


// Protected route example
server.get('/protected-route', authenticateToken, (request, response) => {
    response.json({ status: 'ok', message: 'This is a protected route' });
});

server.listen(port, () => {
    console.log(`App is running on port ${port}`);
});
