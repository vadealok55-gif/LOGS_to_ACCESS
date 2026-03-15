import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

export const googleProvider = new GoogleAuthProvider();

const firebaseConfig = {
    apiKey: import.meta.env.VITE_FIREBASE_API_KEY || "AIzaSyB9ctt45576AnNPgo0siod0eibymJkCOtQ",
    authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN || "nexusguard-hub.firebaseapp.com",
    projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID || "nexusguard-hub",
    storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET || "nexusguard-hub.firebasestorage.app",
    messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID || "659569445164",
    appId: import.meta.env.VITE_FIREBASE_APP_ID || "1:659569445164:web:16681201c91a3d3a4d0489"
};


const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export default app;
