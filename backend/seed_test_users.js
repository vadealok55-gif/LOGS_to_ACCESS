const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

const serviceAccountPath = './serviceAccountKey.json';

if (!fs.existsSync(serviceAccountPath)) {
    console.error('❌ serviceAccountKey.json not found.');
    process.exit(1);
}

admin.initializeApp({
    credential: admin.credential.cert(require(path.resolve(serviceAccountPath))),
    projectId: 'nexusguard-hub'
});

const db = admin.firestore();
const auth = admin.auth();

async function seedUsers() {
    console.log('🚀 Starting user seeding...');

    // 1. Ensure System Admin exists
    const adminEmail = 'vadealok54@gmail.com';
    let adminUid;
    try {
        const userRecord = await auth.getUserByEmail(adminEmail);
        adminUid = userRecord.uid;
    } catch (error) {
        if (error.code === 'auth/user-not-found') {
            const userRecord = await auth.createUser({
                email: adminEmail,
                password: 'password123',
                displayName: 'System Admin'
            });
            adminUid = userRecord.uid;
        } else {
            throw error;
        }
    }

    await db.collection('users').doc(adminUid).set({
        uid: adminUid,
        email: adminEmail,
        displayName: 'System Admin',
        isSystemAdmin: true,
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    console.log(`✅ System Admin configured: ${adminEmail}`);

    // 2. Create 100 test users
    const BATCH_SIZE = 10;
    for (let i = 1; i <= 100; i++) {
        const email = `testuser${i}@nexusguard.io`;
        const displayName = `Test User ${i}`;
        const password = 'password123';

        try {
            let uid;
            try {
                const userRecord = await auth.getUserByEmail(email);
                uid = userRecord.uid;
            } catch (error) {
                if (error.code === 'auth/user-not-found') {
                    const userRecord = await auth.createUser({
                        email,
                        password,
                        displayName
                    });
                    uid = userRecord.uid;
                } else {
                    console.error(`Failed to create/get ${email}:`, error.message);
                    continue;
                }
            }

            await db.collection('users').doc(uid).set({
                uid,
                email,
                displayName,
                isSystemAdmin: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });

            if (i % BATCH_SIZE === 0) {
                console.log(`... seeded ${i} users`);
            }
        } catch (error) {
            console.error(`Error seeding ${email}:`, error.message);
        }
    }

    console.log('✅ Seeding complete! 100 users created/verified.');
    process.exit(0);
}

seedUsers().catch(err => {
    console.error('❌ Seeding failed:', err);
    process.exit(1);
});
