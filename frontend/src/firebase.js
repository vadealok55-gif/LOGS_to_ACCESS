import { initializeApp } from "firebase/app";
import { getAuth, GoogleAuthProvider } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

export const googleProvider = new GoogleAuthProvider();

const firebaseConfig = {
    apiKey: "AIzaSyB9ctt45576AnNPgo0siod0eibymJkCOtQ",
    authDomain: "nexusguard-hub.firebaseapp.com",
    projectId: "nexusguard-hub",
    storageBucket: "nexusguard-hub.firebasestorage.app",
    messagingSenderId: "659569445164",
    appId: "1:659569445164:web:16681201c91a3d3a4d0489"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);
export default app;
