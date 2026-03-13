const admin = require('firebase-admin');

// Initialize Firebase Admin
const fs = require('fs');
const path = require('path');

const serviceAccountPath = './serviceAccountKey.json';

if (fs.existsSync(serviceAccountPath)) {
    admin.initializeApp({
        credential: admin.credential.cert(require(path.resolve(serviceAccountPath))),
        projectId: 'nexusguard-hub'
    });
} else {
    admin.initializeApp({
        projectId: 'nexusguard-hub',
    });
}

const db = admin.firestore();

const seedDatabase = async () => {
    try {
        console.log('🚀 Starting Database Seeding (Firestore)...');

        // 1. Create a System Administrator
        const systemAdminUid = 'ZqEEh69XQORhdZQtwtPoPpFCByK2'; // Updated to Alok Vade's UID
        await db.collection('users').doc(systemAdminUid).set({
            uid: systemAdminUid,
            email: 'alokvade54@gmail.com',
            displayName: 'Alok Vade',
            isSystemAdmin: true,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log('✅ Created System Admin record');

        // 2. Create an Organization (Group)
        const orgRef = await db.collection('organizations').add({
            name: 'Security Ops',
            ownerUid: systemAdminUid,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
        const orgId = orgRef.id;
        console.log(`✅ Created Organization "Security Ops" (Table: organizations, Record: ${orgId})`);

        // 3. Add Members to Group with Roles
        await db.collection('org_members').doc(`${orgId}_${systemAdminUid}`).set({
            orgId: orgId,
            uid: systemAdminUid,
            role: 'Admin',
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });
        console.log('✅ Created Org Member record (Role: Admin)');

        // 4. Populate Resources (Records)
        const sampleResources = [
            { name: 'Firewall Config', type: 'Config', accessLevel: 'private', status: 'active' },
            { name: 'Network Map', type: 'Map', accessLevel: 'public', status: 'active' },
            { name: 'Intrusion Detection Logs', type: 'Log', accessLevel: 'private', status: 'warning' }
        ];

        for (const res of sampleResources) {
            await db.collection('resources').add({
                ...res,
                orgId: orgId,
                tags: ['SECURITY', 'INFRA'],
                traffic: Math.floor(Math.random() * 500) + ' rq/s',
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            });
        }
        console.log(`✅ Added ${sampleResources.length} Resource records to the "resources" table`);

        // 5. Initial Log Entry
        await db.collection('activity_logs').add({
            uid: systemAdminUid,
            email: 'admin@nexusguard.hub',
            action: 'INITIAL_SEED',
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            details: { message: 'Database initialized with seed data' }
        });
        console.log('✅ Created initial Log record');

        console.log('\n🎉 Database Seeding Complete!');
        process.exit(0);
    } catch (error) {
        console.error('❌ Seeding failed:', error);
        process.exit(1);
    }
};

seedDatabase();
