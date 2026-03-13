const admin = require('firebase-admin');
const path = require('path');

const serviceAccountPath = './serviceAccountKey.json';

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(require(path.resolve(serviceAccountPath))),
        projectId: 'nexusguard-hub'
    });
}

const db = admin.firestore();
const auth = admin.auth();

const indianUsers = [
    { name: "Aarav Sharma", email: "aarav.sharma@nexusguard.test", role: "Owner" },
    { name: "Vihaan Gupta", email: "vihaan.gupta@nexusguard.test", role: "Admin" },
    { name: "Advait Rao", email: "advait.rao@nexusguard.test", role: "Manager" },
    { name: "Reyansh Patel", email: "reyansh.patel@nexusguard.test", role: "Developer" },
    { name: "Sai Krishna", email: "sai.krishna@nexusguard.test", role: "Manager" },
    { name: "Ishaan Malhotra", email: "ishaan.malhotra@nexusguard.test", role: "Developer" },
    { name: "Ananya Deshmukh", email: "ananya.deshmukh@nexusguard.test", role: "Admin" },
    { name: "Diya Iyer", email: "diya.iyer@nexusguard.test", role: "Manager" },
    { name: "Myra Reddy", email: "myra.reddy@nexusguard.test", role: "Developer" },
    { name: "Aadhya Joshi", email: "aadhya.joshi@nexusguard.test", role: "Developer" },
    { name: "Kiaan Singh", email: "kiaan.singh@nexusguard.test", role: "Developer" },
    { name: "Vivaan Verma", email: "vivaan.verma@nexusguard.test", role: "Manager" }
];

async function seed() {
    console.log("🚀 Starting Targeted Seeding: Indian Personas...");

    // 1. Create Organization
    const orgId = "bharat_security_org";
    const orgRef = db.collection('organizations').doc(orgId);
    await orgRef.set({
        id: orgId,
        name: "Bharat Security Solutions",
        ownerEmail: "vadealok54@gmail.com",
        ownerName: "System Admin",
        createdAt: admin.firestore.FieldValue.serverTimestamp()
    });
    console.log(`✅ Created Organization: ${orgId}`);

    // 2. Create Users
    for (const data of indianUsers) {
        let userRecord;
        try {
            userRecord = await auth.getUserByEmail(data.email);
            console.log(`User exists: ${data.email}`);
        } catch (err) {
            userRecord = await auth.createUser({
                email: data.email,
                password: "Password123!",
                displayName: data.name
            });
            console.log(`✨ Created User: ${data.email}`);
        }

        const uid = userRecord.uid;

        // Update Firestore User Profile
        await db.collection('users').doc(uid).set({
            uid,
            email: data.email,
            displayName: data.name,
            isSystemAdmin: false,
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        }, { merge: true });

        // Add to Organization
        const memberId = `${orgId}_${uid}`;
        await db.collection('org_members').doc(memberId).set({
            memberId,
            orgId,
            uid,
            email: data.email,
            displayName: data.name,
            role: data.role,
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`   - Assigned ${data.name} as ${data.role}`);
    }

    console.log("\n🎯 Targeted Seeding Complete! 12 Indian personas added to Bharat Security Solutions.");
    process.exit(0);
}

seed().catch(err => {
    console.error("❌ Seeding Failed:", err);
    process.exit(1);
});
