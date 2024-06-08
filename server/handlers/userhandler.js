import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import fs from "fs";
import dotenv from "dotenv";
import { nanoid } from "nanoid";
import { getUserInFirestore, storeUserInFirestore, getUserByField, updateUserProfile, blacklistToken, isTokenBlacklisted } from "../services/storeData.js";

dotenv.config();

const privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8');
const publicKey = fs.readFileSync(process.env.PUBLIC_KEY_PATH, 'utf8');

const ALLOWED_DOMAIN = 'gmail.com';

// JWT functions
function createJWT(data) {
    return jwt.sign(data, privateKey, { algorithm: "RS256" });
}

export async function registerUser(request, response) {
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
}

export async function loginUser(request, response) {
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
}

export async function logoutUser(request, response) {
    const authHeader = request.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token) {
        await blacklistToken(token);
    }
    response.status(200).json({ status: 'ok', message: 'Logged out successfully' });
}

export async function updateProfile(request, response) {
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
}

export async function getUserDetail(request, response) {
    const email = request.user.email;

    try {
        const user = await getUserInFirestore(email);

        if (user.exists) {
            const userData = {
                userId: user.get("userId"),
                username: user.get("username"),
                fullname: user.get("fullname"),
                email: user.get("email"),
            };

            response.status(200).json({ status: "success", user: userData });
        } else {
            response.status(404).json({ status: "error", message: "User not found" });
        }
    } catch (error) {
        response.status(500).json({ status: "error", message: error.message });
    }
}

// Authentication middleware
export async function authenticateToken(request, response, next) {
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
