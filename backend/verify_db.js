const admin = require('firebase-admin');

const path = require('path');
const serviceAccountPath = path.resolve(__dirname, 'serviceAccountKey.json');
const serviceAccount = require(serviceAccountPath);

// Use existing environment variables or standard init
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id,
    });
}

const db = admin.firestore();

async function verifyDB() {
    console.log('--- Database Verification ---');
    try {
        const collections = ['users', 'organizations', 'org_members', 'resources', 'activity_logs'];
        for (const col of collections) {
            console.log(`Checking [${col}]...`);
            const snapshot = await db.collection(col).limit(5).get();
            console.log(`Collection [${col}]: ${snapshot.size} documents found.`);
            snapshot.forEach(doc => {
                console.log(` - ID: ${doc.id}, Data: ${JSON.stringify(doc.data()).substring(0, 100)}...`);
            });
        }
        console.log('--- Verification Complete ---');
    } catch (err) {
        console.error('Firestore Error details:', err);
        process.exit(1);
    }
}

verifyDB();
