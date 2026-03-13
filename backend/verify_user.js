const admin = require('firebase-admin');
const path = require('path');

const serviceAccount = require(path.resolve('./serviceAccountKey.json'));

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();

async function checkUser(email) {
    console.log(`🔍 Searching for user with email: ${email}`);
    const snapshot = await db.collection('users').where('email', '==', email).get();
    
    if (snapshot.empty) {
        console.log('❌ No user found with that email.');
        
        // Let's list all users to see what we have
        console.log('\n👥 Listing first 5 users in database:');
        const allUsers = await db.collection('users').limit(5).get();
        allUsers.forEach(doc => {
            console.log(` - UID: ${doc.id}, Email: ${doc.data().email}`);
        });
    } else {
        snapshot.forEach(doc => {
            console.log(`✅ User Found!`);
            console.log(`UID: ${doc.id}`);
            console.log(`Data:`, JSON.stringify(doc.data(), null, 2));
        });
    }
    process.exit(0);
}

checkUser('vadealok54@gmail.com').catch(err => {
    console.error('Error:', err);
    process.exit(1);
});
