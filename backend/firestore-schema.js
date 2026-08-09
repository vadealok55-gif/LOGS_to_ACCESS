// Firestore Database Schema Initialization for NexusGuard
// This script creates all necessary collections with sample data and indexes

const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

const serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || './serviceAccountKey.json';

console.log('🔍 Initializing Firebase Admin with service account:', serviceAccountPath);

// Initialize Firebase Admin
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

        // List existing collections to check what's already there
        async function setupDatabase() {
            try {
                const collections = await db.listCollections();
                console.log('📡 Existing collections:', collections.map(c => c.id).join(', '));

                // Check if essential collections exist, create if not
                const essentialCollections = [
                    'users',
                    'organizations',
                    'org_members',
                    'groups',
                    'resources',
                    'pending_provisions',
                    'activity_logs',
                    'join_requests',
                    'verification_codes'
                ];

                const existingCollectionIds = collections.map(c => c.id);
                const missingCollections = essentialCollections.filter(
                    id => !existingCollectionIds.includes(id)
                );

                if (missingCollections.length === 0) {
                    console.log('✅ All essential collections already exist');
                    return;
                }

                console.log('📝 Creating missing collections:', missingCollections.join(', '));

                // Create sample data for each collection
                await createSampleData(db, missingCollections);

                console.log('🎉 Database schema setup complete!');

            } catch (error) {
                console.error('❌ Error setting up database:', error);
                if (error.message.includes('NOT_FOUND') || error.code === 5) {
                    console.error('\n💡 PROBABLE CAUSE: The "(default)" database does not exist in this project.');
                    console.error('Please go to https://console.firebase.google.com/u/0/project/' + admin.app().options.projectId + '/firestore and click "Create Database".');
                }
                process.exit(1);
            }
        }

        // Create sample data for collections
        async function createSampleData(db, collections) {
            // 1. Create sample System Admin user
            if (collections.includes('users')) {
                console.log('👤 Creating System Admin user...');
                const systemAdminRef = db.collection('users').doc('sys_admin_001');
                await systemAdminRef.set({
                    uid: 'sys_admin_001',
                    email: 'admin@nexusguard.io',
                    displayName: 'System Administrator',
                    firstName: 'System',
                    lastName: 'Admin',
                    location: 'Global',
                    isEmailVerified: true,
                    isSystemAdmin: true,
                    createdAt: admin.firestore.FieldValue.serverTimestamp()
                });
                console.log('✅ System Admin created');
            }

            // 2. Create sample Organization
            if (collections.includes('organizations')) {
                console.log('🏢 Creating sample organization...');
                const orgRef = db.collection('organizations').doc('org_001');
                await orgRef.set({
                    name: 'Acme Corporation',
                    ownerUid: 'user_001',
                    ownerEmail: 'ceo@acme.com',
                    ownerName: 'John CEO',
                    createdAt: admin.firestore.FieldValue.serverTimestamp()
                });
                console.log('✅ Organization created');
            }

            // 3. Create organization members
            if (collections.includes('org_members')) {
                console.log('👥 Creating organization members...');
                const orgMembers = [
                    {
                        orgId: 'org_001',
                        uid: 'user_001', // CEO/Owner — full privilege set
                        email: 'ceo@acme.com',
                        name: 'John CEO',
                        role: 'Owner',   // Owner role for org creator (not Admin)
                        groupId: null,
                        joinedAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        orgId: 'org_001',
                        uid: 'user_002', // Admin
                        email: 'manager@acme.com',
                        name: 'Jane Manager',
                        role: 'Admin',
                        groupId: 'group_001',
                        joinedAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        orgId: 'org_001',
                        uid: 'user_003', // Developer
                        email: 'dev@acme.com',
                        name: 'Bob Developer',
                        role: 'Developer',
                        groupId: 'group_001',
                        joinedAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        orgId: 'org_001',
                        uid: 'user_004', // Viewer
                        email: 'viewer@acme.com',
                        name: 'Alice Viewer',
                        role: 'Viewer',
                        groupId: 'group_002',
                        joinedAt: admin.firestore.FieldValue.serverTimestamp()
                    }
                ];

                for (const member of orgMembers) {
                    const memberId = `${member.orgId}_${member.uid}`;
                    await db.collection('org_members').doc(memberId).set(member);
                }
                console.log('✅ Organization members created');
            }

            // 4. Create sample user profiles
            if (collections.includes('users')) {
                console.log('👤 Creating user profiles...');
                const users = [
                    {
                        uid: 'user_001',
                        email: 'ceo@acme.com',
                        displayName: 'John CEO',
                        firstName: 'John',
                        lastName: 'CEO',
                        location: 'New York',
                        isEmailVerified: true,
                        isSystemAdmin: false,
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        uid: 'user_002',
                        email: 'manager@acme.com',
                        displayName: 'Jane Manager',
                        firstName: 'Jane',
                        lastName: 'Manager',
                        location: 'San Francisco',
                        isEmailVerified: true,
                        isSystemAdmin: false,
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        uid: 'user_003',
                        email: 'dev@acme.com',
                        displayName: 'Bob Developer',
                        firstName: 'Bob',
                        lastName: 'Developer',
                        location: 'Austin',
                        isEmailVerified: true,
                        isSystemAdmin: false,
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        uid: 'user_004',
                        email: 'viewer@acme.com',
                        displayName: 'Alice Viewer',
                        firstName: 'Alice',
                        lastName: 'Viewer',
                        location: 'Seattle',
                        isEmailVerified: true,
                        isSystemAdmin: false,
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    }
                ];

                for (const user of users) {
                    await db.collection('users').doc(user.uid).set(user);
                }
                console.log('✅ User profiles created');
            }

            // 5. Create sample groups
            if (collections.includes('groups')) {
                console.log('🏷️ Creating sample groups...');
                const groups = [
                    {
                        orgId: 'org_001',
                        name: 'Development Team',
                        privileges: {
                            'READ': true,
                            'WRITE': true,
                            'DELETE': false,
                            'EXECUTE': false,
                            'BILLING': false,
                            'NETWORK': false,
                            'INFRASTRUCTURE': false
                        },
                        createdBy: 'user_002',
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        orgId: 'org_001',
                        name: 'Operations Team',
                        privileges: {
                            'READ': true,
                            'WRITE': false,
                            'DELETE': false,
                            'EXECUTE': false,
                            'BILLING': false,
                            'NETWORK': false,
                            'INFRASTRUCTURE': false
                        },
                        createdBy: 'user_001',
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    }
                ];

                for (const group of groups) {
                    const groupRef = await db.collection('groups').add(group);
                    console.log(`✅ Group created: ${group.name} (ID: ${groupRef.id})`);
                }
            }

            // 6. Create sample resources
            if (collections.includes('resources')) {
                console.log('📦 Creating sample resources...');
                const resources = [
                    {
                        name: 'Web Server',
                        type: 'Server',
                        tags: ['production', 'web', 'critical'],
                        status: 'active',
                        traffic: 'High',
                        accessLevel: 'private',
                        orgId: 'org_001',
                        creatorUid: 'user_002',
                        creatorName: 'Jane Manager',
                        creatorEmail: 'manager@acme.com',
                        allowedGroups: ['group_001'],
                        allowedRoles: ['Admin', 'Owner'],
                        provisionRoles: {},
                        provisionGroupRoles: {},
                        logs: [],
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    },
                    {
                        name: 'Database Cluster',
                        type: 'Database',
                        tags: ['production', 'data', 'critical'],
                        status: 'active',
                        traffic: 'Medium',
                        accessLevel: 'private',
                        orgId: 'org_001',
                        creatorUid: 'user_003',
                        creatorName: 'Bob Developer',
                        creatorEmail: 'dev@acme.com',
                        allowedGroups: ['group_001'],
                        allowedRoles: ['Admin', 'Owner', 'Developer'],
                        provisionRoles: {},
                        provisionGroupRoles: {},
                        logs: [],
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    }
                ];

                for (const resource of resources) {
                    await db.collection('resources').add(resource);
                }
                console.log('✅ Sample resources created');
            }

            // 7. Create sample pending provisions
            if (collections.includes('pending_provisions')) {
                console.log('⏳ Creating sample pending provisions...');
                const provisions = [
                    {
                        name: 'Load Balancer',
                        type: 'Infrastructure',
                        tags: ['staging', 'load-balancing'],
                        status: 'pending_approval',
                        traffic: 'Medium',
                        accessLevel: 'private',
                        orgId: 'org_001',
                        creatorUid: 'user_003',
                        creatorName: 'Bob Developer',
                        creatorEmail: 'dev@acme.com',
                        allowedGroups: ['group_001'],
                        allowedRoles: ['Admin', 'Owner'],
                        stagedAt: admin.firestore.FieldValue.serverTimestamp(),
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    }
                ];

                for (const provision of provisions) {
                    await db.collection('pending_provisions').add(provision);
                }
                console.log('✅ Sample pending provisions created');
            }

            // 8. Create sample join requests
            if (collections.includes('join_requests')) {
                console.log('📋 Creating sample join requests...');
                const joinRequests = [
                    {
                        orgId: 'org_001',
                        orgName: 'Acme Corporation',
                        uid: 'user_005',
                        email: 'newuser@company.com',
                        displayName: 'New User',
                        requestedRole: 'Developer',
                        workDetails: 'Looking to join development team',
                        status: 'pending',
                        createdAt: admin.firestore.FieldValue.serverTimestamp()
                    }
                ];

                for (const request of joinRequests) {
                    await db.collection('join_requests').add(request);
                }
                console.log('✅ Sample join requests created');
            }

            // 9. Create verification_codes placeholder
            if (collections.includes('verification_codes')) {
                console.log('🔑 Initializing verification_codes collection...');
                // Placeholder document to ensure collection exists;
                // real docs are created per-user on demand and auto-deleted.
                await db.collection('verification_codes').doc('_placeholder').set({
                    _info: 'This collection stores short-lived email verification codes.',
                    createdAt: admin.firestore.FieldValue.serverTimestamp()
                });
                console.log('✅ verification_codes initialized');
            }

            // 10. Create sample activity logs
            if (collections.includes('activity_logs')) {
                console.log('📊 Creating sample activity logs...');
                const logs = [
                    {
                        uid: 'user_001',
                        email: 'ceo@acme.com',
                        userName: 'John CEO',
                        action: 'ORG_CREATED',
                        timestamp: admin.firestore.FieldValue.serverTimestamp(),
                        details: { orgName: 'Acme Corporation' },
                        ip: '192.168.1.100',
                        orgId: 'org_001'
                    },
                    {
                        uid: 'user_002',
                        email: 'manager@acme.com',
                        userName: 'Jane Manager',
                        action: 'RESOURCE_CREATED',
                        timestamp: admin.firestore.FieldValue.serverTimestamp(),
                        details: { resourceName: 'Web Server', orgId: 'org_001' },
                        ip: '192.168.1.101',
                        orgId: 'org_001'
                    }
                ];

                for (const log of logs) {
                    await db.collection('activity_logs').add(log);
                }
                console.log('✅ Sample activity logs created');
            }

            console.log('🎉 All sample data created successfully!');
        }

        // Setup indexes guidance
        async function setupIndexes() {
            console.log('\n📋 Composite Index Requirements (defined in firestore.indexes.json):');
            console.log('  org_members:        (orgId, uid), (orgId, role), (orgId, groupId)');
            console.log('  resources:          (orgId, accessLevel), (orgId, createdAt), (orgId, type)');
            console.log('  activity_logs:      (uid, timestamp), (orgId, timestamp), (uid, orgId, timestamp)');
            console.log('  pending_provisions: (orgId, stagedAt), (orgId, status)');
            console.log('  join_requests:      (orgId, status), (uid, status), (orgId, uid, status)');
            console.log('  groups:             (orgId, name)');
            console.log('\n  Deploy indexes: firebase deploy --only firestore:indexes');
        }

        // Run setup
        setupDatabase().then(() => setupIndexes(db)).catch(console.error);

    } catch (e) {
        console.error('❌ Initialization Error:', e.message);
        process.exit(1);
    }
} else {
    console.error('❌ MISSING: serviceAccountKey.json not found in current directory.');
    console.error('Please ensure the Firebase service account key is properly configured.');
    process.exit(1);
}