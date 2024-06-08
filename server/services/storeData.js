import { getFirestore } from "firebase-admin/firestore";
import { customAlphabet } from 'nanoid';

const nanoid = customAlphabet('abcdefghijklmnopqrstuvwxyz0123456789', 10);

// User management functions
export async function storeUserInFirestore(email, username, password) {
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

export async function getUserInFirestore(email) {
    const db = getFirestore();
    return await db.collection("users").doc(email).get();
}

export async function getUserByField(field, value) {
    const db = getFirestore();
    const usersSnapshot = await db.collection("users").where(field, "==", value).get();
    return !usersSnapshot.empty;
}

export async function updateUserProfile(email, updatedFields) {
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
export async function blacklistToken(token) {
    const db = getFirestore();
    await db.collection("blacklistedTokens").doc(token).set({ invalidatedAt: new Date() });
}

export async function isTokenBlacklisted(token) {
    const db = getFirestore();
    const doc = await db.collection("blacklistedTokens").doc(token).get();
    return doc.exists;
}
