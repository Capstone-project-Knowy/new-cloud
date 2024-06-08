import express from "express";
import fs from "fs";
import cors from "cors";
import dotenv from "dotenv";
import { initializeApp, cert } from "firebase-admin/app";
import { Storage } from '@google-cloud/storage';
import userRoutes from './routes/userRoutes.js';

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

server.use(express.json());
server.use(express.urlencoded({ extended: true }));
server.use(cors());

server.use('/api', userRoutes);

server.listen(port, () => {
    console.log(`App is running on port ${port}`);
});
