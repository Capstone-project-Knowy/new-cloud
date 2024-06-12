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

const ALLOWED_DOMAIN = 'gmail.com';

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

server.get("/getUserDetail", authenticateToken, async (request, response) => {
    const email = request.user.email;

    try {
        const user = await getUserInFirestore(email);

        if (user.exists) {
            const userData = {
                userId: user.get("userId"),
                username: user.get("username"),
                fullname: user.get("fullname"), // Assuming fullName is stored in the Firestore document
                email: user.get("email"),
            };

            response.status(200).json({ status: "success", user: userData });
        } else {
            response.status(404).json({ status: "error", message: "User not found" });
        }
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

// Forum management

// Get discussions
server.get("/forum", authenticateToken, async (request, response) => {
    const db = getFirestore();

    try {
        const forumsSnapshot = await db.collection("discussions").get();
        if (forumsSnapshot.empty) {
            return response.status(200).json({ status: "success", forums: "There's no Discussion out here" });
        }

        const forums = forumsSnapshot.docs.map(doc => {
            const data = doc.data();
            return {
                ...data,
                createdAt: moment(data.createdAt.toDate()).format('DD-MM-YYYY HH:mm:ss'), // Format to European date format
                comments: (data.comments || []).map(comment => ({
                    ...comment,
                    createdAt: moment(comment.createdAt.toDate()).format('DD-MM-YYYY HH:mm:ss') // Format to European date format
                }))
            };
        });
        response.status(200).json({ status: "success", forums });
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

server.get("/detailForum/{forumId}", authenticateToken, async (request, response) => {
    const { id: forumId } = request.params; // Extracting forumId from the request parameters
    const db = getFirestore();

    try {
        const forumDoc = await db.collection("discussions").doc(forumId).get();
        if (!forumDoc.exists) {
            return response.status(404).json({ status: "error", message: "Forum not found" });
        }

        const forumData = forumDoc.data();
        const formattedForum = {
            ...forumData,
            createdAt: moment(forumData.createdAt.toDate()).format('DD-MM-YYYY HH:mm:ss'), // Format to European date format
            comments: (forumData.comments || []).map(comment => ({
                ...comment,
                createdAt: moment(comment.createdAt.toDate()).format('DD-MM-YYYY HH:mm:ss') // Format to European date format
            }))
        };

        response.status(200).json({ status: "success", forum: formattedForum });
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

server.get("/comment/{commentId}", authenticateToken, async (request, response) => {
    const { id: forumId } = request.params; // Extracting forumId from the request parameters
    const db = getFirestore();

    try {
        const forumDoc = await db.collection("discussions").doc(forumId).get();
        if (!forumDoc.exists) {
            return response.status(404).json({ status: "error", message: "Forum not found" });
        }

        const forumData = forumDoc.data();
        const formattedComments = (forumData.comments || []).map(comment => ({
            ...comment,
            createdAt: moment(comment.createdAt.toDate()).format('DD-MM-YYYY HH:mm:ss')
        }));

        response.status(200).json({ status: "success", comments: formattedComments });
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

// Create a new discussion
server.post("/addForumDiscussion", authenticateToken, async (request, response) => {
    const { forumTitle, forumContent } = request.body;
    const userId = request.user.userId
    const username = request.user.username
    const forumId = `forum-${nanoid()}`;

    try {
        await storeForumInFirestore(forumId, forumTitle, forumContent, userId, username);
        response.status(200).json({ status: "success", message: "Forum topic created successfully" });
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

// Add a comment to a discussion
server.post("/addForumComments", authenticateToken, async (request, response) => {
    const { forumId, commentContent } = request.body;
    const userId = request.user.userId;
    const username = request.user.username

    try {
        await storeCommentInFirestore(forumId, commentContent, userId, username);
        response.status(200).json({ status: "success", message: "Comment added successfully" });
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
});

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ FITUR UTAMA BELOW APTITUDE & OCEAN Test~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

server.get('/aptitudeQuestions/{testName}', async (request, response) => {
    const { documentName } = request.params;
    const db = getFirestore();

    try {
        const docRef = db.collection('questions').doc(documentName);
        const doc = await docRef.get();

        if (!doc.exists) {
            // Create the document if it does not exist
            await docRef.set({ imageUrls: [] });
            return response.status(404).json({ status: 'error', message: 'Document not found. Initialized with empty imageUrls array.' });
        }

        const data = doc.data();
        if (!data.imageUrls || data.imageUrls.length === 0) {
            return response.status(404).json({ status: 'error', message: 'No image URLs found in the document' });
        }

        response.status(200).json({ status: 'success', image_urls: data.imageUrls });
    } catch (error) {
        response.status(500).json({ status: 'error', message: error.message });
    }
});

server.get('/aptitudeAnswer/{testName}', async (request, response) => {
    const { documentName } = request.params;
    const db = getFirestore();

    try {
        const docRef = db.collection('answerAptitude').doc(documentName);
        const doc = await docRef.get();

        if (!doc.exists) {
            await docRef.set({ answers: [] });
            return response.status(404).json({ status: 'error', message: 'Document not found. Initialized with empty answers array.' });
        }

        const data = doc.data();
        if (!data.answers || data.answers.length === 0) {
            return response.status(404).json({ status: 'error', message: 'Tidak ada KJ' });
        }

        response.status(200).json({ status: 'success', answers: data.answers });
    } catch (error) {
        response.status(500).json({ status: 'error', message: error.message });
    }
});

// Endpoint untuk menyimpan skor aptitude & ocean
server.post('/saveScore/{testName}', authenticateToken, async (request, response) => {
    const { documentName } = request.params;
    const { score } = request.body;
    const userId = request.user.userId;
    const db = getFirestore();

    try {
        const scoreRef = db.collection('score').doc(documentName);

        // Retrieve the existing score document
        const doc = await scoreRef.get();

        let scores = [];
        if (doc.exists) {
            const data = doc.data();
            scores = data.scores || [];
        } else {
            // Initialize the document with an empty scores array if it doesn't exist
            await scoreRef.set({ scores: [] });
        }

        // Check if userId already exists in the scores array
        const existingScoreIndex = scores.findIndex(score => score.userId === userId);

        const newScore = {
            userId,
            score,
            timestamp: new Date().toLocaleString('en-GB', { timeZone: 'Europe/London' }) // Convert timestamp to European format
        };

        if (existingScoreIndex >= 0) {
            // Overwrite the existing score for the userId
            scores[existingScoreIndex] = newScore;
        } else {
            // Add the new score entry
            scores.push(newScore);
        }

        // Save the updated scores array to Firestore
        await scoreRef.set({ scores }, { merge: true });

        response.status(200).json({ status: 'success', message: 'Score saved successfully', scores });
    } catch (error) {
        response.status(500).json({ status: 'error', message: error.message });
    }
});

// mengambil skor melalui test name aptitude & ocean
server.get('/showScore/{testName}', authenticateToken, async (request, response) => {
    const { documentName } = request.params;
    const db = getFirestore();

    try {
        const scoreRef = db.collection('score').doc(documentName);
        const doc = await scoreRef.get();

        if (!doc.exists) {
            return response.status(404).json({ status: 'error', message: 'Document not found' });
        }

        const data = doc.data();
        if (!data.scores || data.scores.length === 0) {
            return response.status(404).json({ status: 'error', message: 'No scores found in the document' });
        }

        response.status(200).json({ status: 'success', scores: data.scores });
    } catch (error) {
        response.status(500).json({ status: 'error', message: error.message });
    }
});

// mengambil skor melalui userId 
server.get('/scoreShow/{userId}', authenticateToken, async (request, response) => {
    const { userId } = request.params;
    const db = getFirestore();

    try {
        const scoresCollection = db.collection('score');
        const scoresSnapshot = await scoresCollection.get();
        let userScores = [];

        if (scoresSnapshot.empty) {
            return response.status(404).json({ status: 'error', message: 'No scores found in the collection' });
        }

        scoresSnapshot.forEach(doc => {
            const data = doc.data();
            const scores = data.scores || [];
            const userScore = scores.find(score => score.userId === userId);

            if (userScore) {
                userScores.push({
                    documentName: doc.id,
                    score: userScore.score,
                });
            }
        });

        if (userScores.length === 0) {
            return response.status(404).json({ status: 'error', message: 'No scores found for the specified userId' });
        }

        // Tambahkan userId ke dalam respons
        response.status(200).json({ status: 'success', userId, scores: userScores });
    } catch (error) {
        response.status(500).json({ status: 'error', message: error.message });
    }
});

// UNCOMMENT SINTAKS DIBAWAH JIKA INGIN INPUT IMAGE URL

// server.post('/uploadImageUrl', async (request, response) => {
//     const { imageUrl } = request.body;
//     const db = getFirestore();

//     try {
//         const docRef = db.collection('questions').doc('Verbal Reasoning Test');
//         const doc = await docRef.get();

//         let imageUrls = [];
//         if (doc.exists) {
//             const data = doc.data();
//             imageUrls = data.imageUrls || [];
//         } else {
//             // Initialize the document with an empty imageUrls array if it doesn't exist
//             await docRef.set({ imageUrls: [] });
//         }

//         imageUrls.push(imageUrl);  // Add new image URL to the end
//         if (imageUrls.length > 10) {
//             imageUrls.shift();  // Remove the oldest image URL if the array exceeds 10
//         }

//         await docRef.set({ imageUrls }, { merge: true });
//         response.status(200).json({ status: 'success', message: 'Image URL uploaded successfully', image_urls: imageUrls });
//     } catch (error) {
//         response.status(500).json({ status: 'error', message: error.message });
//     }
// });

// server.post('/uploadAnswer', async (request, response) => {
//     const { answer } = request.body;
//     const db = getFirestore();

//     try {
//         const docRef = db.collection('answerAptitude').doc('Verbal Reasoning Test');
//         const doc = await docRef.get();

//         let answers = [];
//         if (doc.exists) {
//             const data = doc.data();
//             answers = data.answers || [];
//         } else {
//             // Initialize the document with an empty answers array if it doesn't exist
//             await docRef.set({ answers: [] });
//         }

//         answers.push(answer);  // Add new image URL to the end
//         if (answers.length > 10) {
//             answers.shift();  // Remove the oldest image URL if the array exceeds 10
//         }

//         await docRef.set({ answers }, { merge: true });
//         response.status(200).json({ status: 'success', message: 'Jawaban telah di up', answers: answers });
//     } catch (error) {
//         response.status(500).json({ status: 'error', message: error.message });
//     }
// });

server.get('/protected-route', authenticateToken, (request, response) => {
    response.json({ status: 'ok', message: 'This is a protected route' });
});

server.listen(port, () => {
    console.log(`App is running on port ${port}`);
});