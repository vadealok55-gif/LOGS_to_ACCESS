const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

const serviceAccountPath = './serviceAccountKey.json';
console.log('🔍 Checking for service account at:', path.resolve(serviceAccountPath));

if (fs.existsSync(serviceAccountPath)) {
    try {
        const serviceAccount = require(path.resolve(serviceAccountPath));
        console.log('📄 Service Account Project ID:', serviceAccount.project_id);

        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId: serviceAccount.project_id
        });
        console.log('🚀 Firebase Admin Initialized.');

        const db = admin.firestore();
        console.log('📡 Attempting to list collections to verify database existence...');

        db.listCollections()
            .then(collections => {
                console.log('✅ Success! Found collections:', collections.length);
                collections.forEach(c => console.log(' - ', c.id));
                process.exit(0);
            })
            .catch(err => {
                console.error('\n❌ FIRESTORE ERROR DETECTED:');
                console.error('Code:', err.code);
                console.error('Message:', err.message);

                if (err.message.includes('NOT_FOUND') || err.code === 5) {
                    console.error('\n💡 PROBABLE CAUSE: The "(default)" database does not exist in this project.');
                    console.error('Please go to https://console.firebase.google.com/u/0/project/' + serviceAccount.project_id + '/firestore and click "Create Database".');
                } else if (err.message.includes('PERMISSION_DENIED')) {
                    console.error('\n💡 PROBABLE CAUSE: The service account does not have "Cloud Datastore Owner" or "Firebase Admin" permissions.');
                }
                process.exit(1);
            });
    } catch (e) {
        console.error('❌ Initialization Error:', e.message);
        process.exit(1);
    }
} else {
    console.error('❌ MISSING: serviceAccountKey.json not found in current directory.');
    process.exit(1);
}