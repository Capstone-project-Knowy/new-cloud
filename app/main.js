import express from "express";
import fs from "fs";
import jwt from "jsonwebtoken";
import { v4 as uuidv4 } from "uuid";
import cors from "cors";
import bcrypt from "bcrypt";
import { getFirestore } from "firebase-admin/firestore";
import { initializeApp, cert } from "firebase-admin/app";
import dotenv from 'dotenv';

dotenv.config();
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

initializeApp({
    credential: cert(serviceAccount),
});

const server = express();
const port = process.env.PORT || 8080;

const privateKey = fs.readFileSync("private.key");
const publicKey = fs.readFileSync("private.key.pub");

server.use(express.json());
server.use(cors());

// User management functions

async function storeUserInFirestore(username, email, password) {
    const db = getFirestore();
    const userRef = db.collection("users").doc(email);

    try {
        await userRef.set({
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
    return jwt.sign(data, privateKey, { algorithm: "RS256" });
}

function verifyJWT(token) {
    return jwt.verify(token, publicKey);
}

// User registration and login

server.post("/register", async (request, response) => {
    try {
        const { username, email, password } = request.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        await storeUserInFirestore(username, email, hashedPassword);
        response.status(200).json({ status: "ok" });
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

server.post("/login", async (request, response) => {
    try {
        const { email, password } = request.body;
        const user = await getUserInFirestore(email);

        if (user.exists && (await bcrypt.compare(password, user.get("password")))) {
            response.status(200).json({ status: "ok", token: createJWT({ email }) });
        } else {
            response.status(403).json({ status: "error", message: "Invalid password or email" });
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

server.put('/profile', authenticateToken, async (req, res) => {
    const email = req.user.email;
    const { username, age, gender } = req.body;
    const updatedFields = {};

    if (username) updatedFields.username = username;
    if (age) updatedFields.age = age;
    if (gender) updatedFields.gender = gender;

    try {
        await updateUserProfile(email, updatedFields);
        res.status(200).send('User profile updated successfully');
    } catch (error) {
        console.error(error);
        res.status(500).send('Error updating user profile');
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
