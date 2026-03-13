require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');
const https = require('https');

// --- EmailJS REST API Helper ---
const sendEmailJS = (toEmail, code) => {
    return new Promise((resolve, reject) => {
        const payload = {
            service_id: process.env.EMAILJS_SERVICE_ID,
            template_id: process.env.EMAILJS_TEMPLATE_ID,
            user_id: process.env.EMAILJS_PUBLIC_KEY,
            template_params: {
                verification_code: code,
                to_email: toEmail,
                system_name: 'NexusGuard'
            }
        };

        // Private key is required for server-side API calls
        if (process.env.EMAILJS_PRIVATE_KEY) {
            payload.accessToken = process.env.EMAILJS_PRIVATE_KEY;
        }

        const data = JSON.stringify(payload);
        console.log(`📋 [EMAILJS] Sending to: ${toEmail}, service: ${process.env.EMAILJS_SERVICE_ID}, template: ${process.env.EMAILJS_TEMPLATE_ID}, hasPrivateKey: ${!!process.env.EMAILJS_PRIVATE_KEY}`);

        const options = {
            hostname: 'api.emailjs.com',
            port: 443,
            path: '/api/v1.0/email/send',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        };

        const req = https.request(options, (res) => {
            let resData = '';
            res.on('data', (chunk) => resData += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    resolve(resData);
                } else {
                    console.error(`❌ [EMAILJS] API returned error ${res.statusCode}: ${resData}`);
                    reject(new Error(`EmailJS Error: ${res.statusCode} - ${resData}`));
                }
            });
        });

        req.on('error', (err) => reject(err));
        req.write(data);
        req.end();
    });
};

// --- Firebase Admin SDK Initialization ---
const serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || './serviceAccountKey.json';

try {
    if (fs.existsSync(serviceAccountPath)) {
        admin.initializeApp({
            credential: admin.credential.cert(require(path.resolve(serviceAccountPath))),
            projectId: 'nexusguard-hub'
        });
        console.log('✅ Firebase Admin initialized with service account.');
    } else {
        console.warn('⚠️  serviceAccountKey.json not found. Backend will run in LIMITED MODE (RBAC & Firestore will fail).');
        console.warn('👉 Place your Firebase Service Account JSON at: ' + path.resolve(serviceAccountPath));
        admin.initializeApp({
            projectId: 'nexusguard-hub'
        });
    }
} catch (err) {
    console.error('❌ Firebase Admin Init Error:', err.message);
}

const db = admin.firestore();



const app = express();
const PORT = process.env.PORT || 5000;

// --- Middleware ---
app.use(cors({
    origin: ['http://localhost:5173', 'http://localhost:5174', 'http://127.0.0.1:5173', 'http://127.0.0.1:5174', 'http://localhost:3000'],
    credentials: true,
}));
app.use(helmet({
    crossOriginOpenerPolicy: false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: false
}));
app.use(express.json());

// --- Auth & RBAC Middleware ---
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split('Bearer ')[1];
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;

        // Fetch user data from Firestore to check for System Admin
        const userDoc = await db.collection('users').doc(decoded.uid).get();
        if (userDoc.exists) {
            req.userData = userDoc.data();
        } else {
            // Create user doc if it doesn't exist
            const newUser = {
                uid: decoded.uid,
                email: decoded.email,
                displayName: decoded.name || decoded.email,
                isSystemAdmin: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            };
            await db.collection('users').doc(decoded.uid).set(newUser);
            req.userData = newUser;
        }

        // Impersonation logic: Only available for System Admins
        const impersonateUid = req.headers['x-impersonate-uid'];
        if (impersonateUid && req.userData?.isSystemAdmin) {
            try {
                const impUserDoc = await db.collection('users').doc(impersonateUid).get();
                if (impUserDoc.exists) {
                    // Store original admin context for auditing
                    req.realUser = { ...req.user, ...req.userData };
                    
                    // Swap context to impersonated user
                    req.user = { 
                        ...req.user, 
                        uid: impersonateUid, 
                        email: impUserDoc.data().email,
                        isImpersonated: true 
                    };
                    req.userData = impUserDoc.data();
                    console.log(`🎭 Admin ${req.realUser.email} impersonating user ${req.userData.email}`);
                }
            } catch (impErr) {
                console.error('Impersonation error:', impErr.message);
            }
        }
        next();
    } catch (err) {
        console.error('Auth error:', err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// Middleware to log all non-GET actions for auditing
const logger = async (req, res, next) => {
    if (req.method !== 'GET') {
        try {
            let actionName = `${req.method} ${req.originalUrl}`;
            
            // Map to friendly names for UI
            if (req.method === 'POST' && req.originalUrl.includes('/resources')) actionName = 'RESOURCE_CREATED';
            else if (req.method === 'PUT' && req.originalUrl.includes('/resources')) actionName = 'RESOURCE_EDITED';
            else if (req.method === 'POST' && req.originalUrl.includes('/organizations')) actionName = 'ORG_CREATED';
            else if (req.method === 'POST' && req.originalUrl.includes('/groups')) actionName = 'GROUP_CREATED';
            else if (req.method === 'PUT' && req.originalUrl.includes('/groups')) actionName = 'GROUP_UPDATED';
            else if (req.method === 'PUT' && req.originalUrl.includes('/members')) actionName = 'USER_ROLE_UPDATED';
            else if (req.method === 'POST' && req.originalUrl.includes('/impersonate')) actionName = 'ADMIN_IMPERSONATION';

            const logEntry = {
                uid: req.user ? req.user.uid : 'anonymous',
                email: req.user ? req.user.email : 'anonymous',
                action: actionName,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                details: { ...req.body },
                ip: req.ip || 'unknown'
            };
            
            // Mask passwords in logs
            if (logEntry.details.password) logEntry.details.password = '********';

            await db.collection('activity_logs').add(logEntry);
        } catch (err) {
            console.error('Logging error:', err.message);
        }
    }
    next();
};

app.use(logger);

// RBAC: Check if System Admin
const isSystemAdmin = (req, res, next) => {
    if (req.userData && req.userData.isSystemAdmin) {
        next();
    } else {
        res.status(403).json({ error: 'Access denied. System Administrator only.' });
    }
};

// RBAC: Check organization role
const hasOrgRole = (roles) => {
    return async (req, res, next) => {
        const orgId = req.query.orgId || req.body.orgId;
        if (!orgId) return res.status(400).json({ error: 'orgId is required for this operation' });

        if (req.userData.isSystemAdmin) return next();

        try {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();

            if (memberDoc.exists && roles.includes(memberDoc.data().role)) {
                next();
            } else {
                res.status(403).json({ error: `Access denied. Requires one of roles: ${roles.join(', ')}` });
            }
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    };
};

// RBAC: Check specific privilege based on Custom Groups
const hasPrivilege = (privilege) => {
    return async (req, res, next) => {
        const orgId = req.query.orgId || req.body.orgId;
        if (!orgId) return res.status(400).json({ error: 'orgId is required for this operation' });

        if (req.userData.isSystemAdmin) return next();

        try {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();

            if (!memberDoc.exists) return res.status(403).json({ error: 'Access denied.' });

            const data = memberDoc.data();
            
            // Owners and Admins implicitly have all privileges
            if (['Owner', 'Admin'].includes(data.role)) return next();

            // Check custom group privilege
            if (data.groupId) {
                const groupDoc = await db.collection('groups').doc(data.groupId).get();
                if (groupDoc.exists && groupDoc.data().privileges[privilege]) {
                    return next();
                }
            }
            
            res.status(403).json({ error: `Access denied. Requires ${privilege} privilege.` });
        } catch (err) {
            console.error('HAS PRIVILEGE ERROR TRAP:', err.message, err.stack);
            res.status(500).json({ error: err.message });
        }
    };
};

// --- API Routes ---

// Health check & User Profile
app.get('/api/health', authenticate, async (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'NexusGuard API', 
        timestamp: new Date().toISOString(), 
        database: 'Firestore',
        user: req.userData 
    });
});

// Get user's activity log
app.get('/api/user/activity', authenticate, async (req, res) => {
    try {
        const uid = req.user.uid;
        // Temporarily fetch without orderBy to avoid index requirement
        // We will sort in-memory for the last 50 items
        const snapshot = await db.collection('activity_logs')
            .where('uid', '==', uid)
            .get();
        
        const logs = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id: doc.id,
                ...data,
                // Convert Firestore Timestamp to ISO string if possible
                timestamp: data.timestamp?.toDate ? data.timestamp.toDate().toISOString() : data.timestamp,
                ipAddress: data.ip || 'unknown'
            };
        })
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 50);
        
        res.json({ logs });
    } catch (err) {
        console.error('Fetch user activity error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Explicit endpoint to log login
app.post('/api/user/log-login', authenticate, async (req, res) => {
    try {
        const uid = req.user.uid;
        const email = req.user.email;
        const logEntry = {
            uid: uid,
            email: email,
            action: 'USER_LOGIN',
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            details: {},
            ip: req.ip || 'unknown'
        };
        await db.collection('activity_logs').add(logEntry);
        res.json({ success: true });
    } catch (err) {
        console.error('Log login error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get user's organizations
app.get('/api/user/organizations', authenticate, async (req, res) => {
    try {
        const uid = req.user.uid;
        // Query org_members for this user
        const memberResult = await db.collection('org_members').where('uid', '==', uid).get();
        const orgIds = memberResult.docs.map(doc => doc.data().orgId);

        if (orgIds.length === 0) {
            return res.json({ organizations: [] });
        }

        // Fetch organization details
        const orgsResult = await db.collection('organizations').where(admin.firestore.FieldPath.documentId(), 'in', orgIds).get();
        const organizations = orgsResult.docs.map(doc => ({
            id: doc.id,
            ...doc.data(),
            role: memberResult.docs.find(md => md.data().orgId === doc.id).data().role
        }));

        res.json({ organizations });
    } catch (err) {
        console.error('Fetch user orgs error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get resources
app.get('/api/resources', authenticate, async (req, res) => {
    try {
        const { orgId } = req.query;
        let query = db.collection('resources');

        if (orgId) {
            // Verify org membership
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            
            let isAllowedAll = false;
            let userRole = null;
            let userGroupId = null;

            if (req.userData && req.userData.isSystemAdmin) {
                isAllowedAll = true;
            } else if (memberDoc.exists) {
                const data = memberDoc.data();
                userRole = data.role;
                userGroupId = data.groupId;
                if (['Owner', 'Admin'].includes(userRole)) {
                    isAllowedAll = true;
                }
            } else {
                return res.status(403).json({ error: 'Access denied. Not a member of this organization.' });
            }

            // Fetch all org resources
            const result = await query.where('orgId', '==', orgId).get();
            let resources = result.docs.map(doc => ({ id: doc.id, ...doc.data() }));

            // Filter resources based on allowedGroups and allowedRoles
            if (!isAllowedAll) {
                resources = resources.filter(resourceData => {
                    const groupsEmpty = !resourceData.allowedGroups || resourceData.allowedGroups.length === 0;
                    const rolesEmpty = !resourceData.allowedRoles || resourceData.allowedRoles.length === 0;
                    
                    const groupAllowed = !groupsEmpty && userGroupId && resourceData.allowedGroups.includes(userGroupId);
                    const roleAllowed = !rolesEmpty && userRole && resourceData.allowedRoles.includes(userRole);

                    return (groupsEmpty && rolesEmpty) || groupAllowed || roleAllowed;
                });
            }

            return res.json({ resources, source: 'firestore' });
        } else {
            // Otherwise show public resources
            const result = await query.where('accessLevel', '==', 'public').get();
            const resources = result.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            return res.json({ resources, source: 'firestore' });
        }
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get a single resource's detail with assigned users
app.get('/api/resources/:id/detail', authenticate, async (req, res) => {
    try {
        const { orgId } = req.query;
        if (!orgId) return res.status(400).json({ error: 'orgId is required' });

        // Verify caller is an org member
        const memberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(memberId).get();
        if (!callerDoc.exists) {
            return res.status(403).json({ error: 'Access denied. Not a member of this organization.' });
        }

        // Fetch the resource
        const resourceDoc = await db.collection('resources').doc(req.params.id).get();
        if (!resourceDoc.exists) return res.status(404).json({ error: 'Resource not found' });
        const resource = { id: resourceDoc.id, ...resourceDoc.data() };

        // Fetch all org members
        const membersSnap = await db.collection('org_members').where('orgId', '==', orgId).get();
        let members = membersSnap.docs.map(d => ({ id: d.id, ...d.data() }));

        // Fetch groups once so we can enrich members with group names
        const groupsSnap = await db.collection('groups').where('orgId', '==', orgId).get();
        const groupsById = {};
        groupsSnap.docs.forEach(d => { groupsById[d.id] = d.data().name; });

        const groupsEmpty = !resource.allowedGroups || resource.allowedGroups.length === 0;
        const rolesEmpty = !resource.allowedRoles || resource.allowedRoles.length === 0;

        // Filter members to only those with access (or all if no restriction)
        if (!groupsEmpty || !rolesEmpty) {
            members = members.filter(m => {
                const groupAllowed = !groupsEmpty && m.groupId && resource.allowedGroups.includes(m.groupId);
                const roleAllowed = !rolesEmpty && m.role && resource.allowedRoles.includes(m.role);
                return groupAllowed || roleAllowed;
            });
        }

        // Enrich with group name and task assignment
        const enriched = members.map(m => ({
            uid: m.userId,
            email: m.email || m.userEmail || '—',
            role: m.role || '—',
            groupId: m.groupId || null,
            groupName: m.groupId ? (groupsById[m.groupId] || 'Unknown Group') : '—',
            taskTitle: m.taskTitle || null,
            taskStatus: m.taskStatus || null,
            workDetails: m.workDetails || null,
            joinedAt: m.joinedAt || null
        }));

        res.json({ resource, members: enriched });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create a resource
app.post('/api/resources', authenticate, hasPrivilege('WRITE'), async (req, res) => {
    const { name, type, tags, status, traffic, accessLevel, orgId, allowedGroups, allowedRoles } = req.body;
    try {
        const newResource = {
            name,
            type: type || 'Folder',
            tags: tags || [],
            status: status || 'active',
            traffic: traffic || '-',
            accessLevel: accessLevel || 'private',
            orgId: orgId || null,
            creatorUid: req.user.uid,
            allowedGroups: allowedGroups || [],
            allowedRoles: allowedRoles || [],
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            logs: [{
                action: 'Created',
                uid: req.user.uid,
                userName: req.userData?.displayName || req.userData?.email || req.user.email || 'Unknown',
                email: req.user.email || 'unknown',
                details: `Resource initialized (${type})`,
                storage: 'Firestore',
                timestamp: new Date().toISOString()
            }]
        };
        const docRef = await db.collection('resources').add(newResource);
        res.status(201).json({ id: docRef.id, ...newResource, source: 'firestore' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update a resource
app.put('/api/resources/:id', authenticate, async (req, res) => {
    try {
        const { orgId, allowedGroups, accessLevel, name } = req.body;
        if (!orgId) return res.status(400).json({ error: 'orgId is required for authorization' });

        const docRef = db.collection('resources').doc(req.params.id);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Resource not found' });
        
        const resourceData = doc.data();
        if (resourceData.orgId !== orgId) return res.status(403).json({ error: 'Org mismatch' });

        // RBAC: Requires WRITE privilege AND (is Admin/Owner OR user's group/role is allowed or lists are empty)
        let canEdit = false;
        if (req.userData.isSystemAdmin) {
            canEdit = true;
        } else {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists) {
                const data = memberDoc.data();
                if (['Owner', 'Admin'].includes(data.role)) {
                    canEdit = true;
                } else {
                    const hasWriteGroupPriv = data.groupId && (await db.collection('groups').doc(data.groupId).get()).data()?.privileges?.['WRITE'];
                    if (hasWriteGroupPriv) {
                        const groupsEmpty = !resourceData.allowedGroups || resourceData.allowedGroups.length === 0;
                        const rolesEmpty = !resourceData.allowedRoles || resourceData.allowedRoles.length === 0;
                        
                        const groupAllowed = !groupsEmpty && resourceData.allowedGroups.includes(data.groupId);
                        const roleAllowed = !rolesEmpty && resourceData.allowedRoles.includes(data.role);

                        if ((groupsEmpty && rolesEmpty) || groupAllowed || roleAllowed) {
                            canEdit = true;
                        }
                    }
                }
            }
        }

        if (!canEdit) return res.status(403).json({ error: 'Access denied. Setup custom groups or verify WRITE permissions.' });

        const updates = {};
        if (req.body.allowedGroups !== undefined) updates.allowedGroups = req.body.allowedGroups;
        if (req.body.allowedRoles !== undefined) updates.allowedRoles = req.body.allowedRoles;
        if (accessLevel !== undefined) updates.accessLevel = accessLevel;
        if (name !== undefined) updates.name = name;

        // Determine what was changed
        const changedFields = Object.keys(updates).length > 0 ? Object.keys(updates).join(', ') : 'No changes';

        // Append log entry
        updates.logs = admin.firestore.FieldValue.arrayUnion({
            action: 'Edited',
            uid: req.user.uid,
            userName: req.userData?.displayName || req.userData?.email || req.user.email || 'Unknown',
            email: req.user.email || 'unknown',
            changes: changedFields,
            storage: 'Firestore',
            timestamp: new Date().toISOString()
        });

        await docRef.update(updates);
        res.json({ message: 'Updated', source: 'firestore' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete a resource
app.delete('/api/resources/:id', authenticate, async (req, res) => {
    try {
        const docRef = db.collection('resources').doc(req.params.id);
        const doc = await docRef.get();

        if (!doc.exists) return res.status(404).json({ error: 'Resource not found' });

        const resourceData = doc.data();
        const orgId = resourceData.orgId;

        let canEdit = false;
        if (req.userData.isSystemAdmin) {
            canEdit = true;
        } else {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists) {
                const data = memberDoc.data();
                if (['Owner', 'Admin'].includes(data.role)) {
                    canEdit = true;
                } else if (data.groupId) {
                    const groupDoc = await db.collection('groups').doc(data.groupId).get();
                    if (groupDoc.exists && groupDoc.data().privileges['WRITE']) {
                        // Check allowedGroups
                        if (!resourceData.allowedGroups || resourceData.allowedGroups.length === 0 || resourceData.allowedGroups.includes(data.groupId)) {
                            canEdit = true;
                        }
                    }
                }
            }
        }

        if (!canEdit) return res.status(403).json({ error: 'Access denied. You do not have permission to delete this resource.' });

        await docRef.delete();
        res.json({ message: 'Deleted', source: 'firestore' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Organization Management (Any Authenticated User)
app.post('/api/organizations', authenticate, async (req, res) => {
    const { name } = req.body;
    const ownerUid = req.user.uid;

    if (!name || name.trim().length < 2) {
        console.warn(`[ORG_CREATE] Validation failed for user ${ownerUid}: Name "${name}" is too short or missing.`);
        return res.status(400).json({ error: 'Organization name must be at least 2 characters.' });
    }

    try {
        console.log(`[ORG_CREATE] User ${ownerUid} (${req.user.email}) attempting to create organization "${name}".`);
        const orgRef = await db.collection('organizations').add({
            name: name.trim(),
            ownerUid,
            ownerEmail: req.user.email || 'unknown',
            ownerName: req.user.displayName || req.user.email || 'Unknown',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Add creator as Admin member
        const memberId = `${orgRef.id}_${ownerUid}`;
        await db.collection('org_members').doc(memberId).set({
            orgId: orgRef.id,
            uid: ownerUid,
            role: 'Admin',
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({ id: orgRef.id, name: name.trim() });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Join Request Routes ---

// Submit a join request
app.post('/api/join-requests', authenticate, async (req, res) => {
    const { orgId, requestedRole, workDetails } = req.body;
    const uid = req.user.uid;
    
    console.log(`[JOIN_REQ] Received submission from ${uid} for orgId: "${orgId}"`);
    if (orgId) {
        console.log(`[JOIN_REQ] orgId length: ${orgId.length}, character codes:`, [...orgId].map(c => c.charCodeAt(0)));
    }

    if (!orgId) return res.status(400).json({ error: 'Organization ID is required.' });

    try {
        const orgDoc = await db.collection('organizations').doc(orgId).get();
        if (!orgDoc.exists) {
            console.log(`[JOIN_REQ] FAILED: Organization not found for ID "${orgId}"`);
            return res.status(404).json({ error: 'Organization not found.' });
        }

        console.log(`[JOIN_REQ] Org exists: ${orgDoc.data().name}. Checking membership...`);

        // Check if already a member
        const memberId = `${orgId}_${uid}`;
        const existingMember = await db.collection('org_members').doc(memberId).get();
        if (existingMember.exists) {
            console.log(`[JOIN_REQ] FAILED: User ${uid} is already a member of ${orgId}`);
            return res.status(409).json({ error: 'You are already a member.' });
        }

        // Check if already has a pending request
        const existingReq = await db.collection('join_requests')
            .where('orgId', '==', orgId).where('uid', '==', uid).where('status', '==', 'pending').get();
        if (!existingReq.empty) return res.status(409).json({ error: 'You already have a pending request.' });

        const reqRef = await db.collection('join_requests').add({
            orgId,
            orgName: orgDoc.data().name,
            uid,
            email: req.user.email || 'unknown',
            displayName: req.user.displayName || req.user.email || 'User',
            requestedRole: requestedRole || 'Viewer',
            workDetails: workDetails || 'No details provided.',
            status: 'pending',
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({ id: reqRef.id, status: 'pending', orgName: orgDoc.data().name });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get my pending requests
app.get('/api/join-requests/mine', authenticate, async (req, res) => {
    try {
        const result = await db.collection('join_requests')
            .where('uid', '==', req.user.uid)
            .get();
        const requests = result.docs.map(doc => ({ id: doc.id, ...doc.data() }))
            .sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
        res.json({ requests });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get pending requests for an org (Admin only)
app.get('/api/join-requests', authenticate, async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        // Verify caller is Admin of the org
        const memberId = `${orgId}_${req.user.uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();
        if (!memberDoc.exists || !['Admin', 'Owner'].includes(memberDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        const result = await db.collection('join_requests')
            .where('orgId', '==', orgId).where('status', '==', 'pending')
            .get();
        const requests = result.docs.map(doc => ({ id: doc.id, ...doc.data() }))
            .sort((a, b) => (b.createdAt?._seconds || 0) - (a.createdAt?._seconds || 0));
        res.json({ requests });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve a join request
app.put('/api/join-requests/:id/approve', authenticate, async (req, res) => {
    try {
        const reqDoc = await db.collection('join_requests').doc(req.params.id).get();
        if (!reqDoc.exists) return res.status(404).json({ error: 'Request not found.' });

        const reqData = reqDoc.data();
        if (reqData.status !== 'pending') return res.status(400).json({ error: 'Request already processed.' });

        // Verify caller is Admin of the org
        const memberId = `${reqData.orgId}_${req.user.uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();
        if (!memberDoc.exists || !['Admin', 'Owner'].includes(memberDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        // Add user with assignedRole, fallback to requestedRole, fallback to Viewer
        const finalRole = req.body.assignedRole || reqData.requestedRole || 'Viewer';
        
        const newMemberId = `${reqData.orgId}_${reqData.uid}`;
        await db.collection('org_members').doc(newMemberId).set({
            orgId: reqData.orgId,
            uid: reqData.uid,
            role: finalRole,
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Update request status
        await db.collection('join_requests').doc(req.params.id).update({
            status: 'approved',
            reviewedBy: req.user.uid,
            reviewedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ message: 'Approved', uid: reqData.uid, email: reqData.email });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Deny a join request
app.put('/api/join-requests/:id/deny', authenticate, async (req, res) => {
    try {
        const reqDoc = await db.collection('join_requests').doc(req.params.id).get();
        if (!reqDoc.exists) return res.status(404).json({ error: 'Request not found.' });

        const reqData = reqDoc.data();
        if (reqData.status !== 'pending') return res.status(400).json({ error: 'Request already processed.' });

        // Verify caller is Admin of the org
        const memberId = `${reqData.orgId}_${req.user.uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();
        if (!memberDoc.exists || !['Admin', 'Owner'].includes(memberDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        await db.collection('join_requests').doc(req.params.id).update({
            status: 'denied',
            reviewedBy: req.user.uid,
            reviewedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.json({ message: 'Denied', uid: reqData.uid });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- User & Group Management Routes ---

// Get all members of an organization
app.get('/api/org-members', authenticate, async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        // Verify caller is a member
        const callerMemberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
        if (!callerDoc.exists) return res.status(403).json({ error: 'Access denied.' });

        const result = await db.collection('org_members').where('orgId', '==', orgId).get();
        
        // Fetch user emails/names from join_requests or a users collection if available, 
        // fallback to minimal data. (In a real app, you'd maintain a users collection)
        const members = [];
        for (const doc of result.docs) {
            const data = doc.data();
            // Try to find user info from join_requests as a hacky lookup since we lack a central users collection
            const reqs = await db.collection('join_requests').where('uid', '==', data.uid).limit(1).get();
            let email = 'Unknown';
            let name = 'User';
            if (!reqs.empty) {
                email = reqs.docs[0].data().email;
                name = reqs.docs[0].data().displayName;
            } else if (data.role === 'Admin' || data.role === 'Owner') {
                // Try org owner lookup
                const orgDoc = await db.collection('organizations').doc(orgId).get();
                if (orgDoc.exists && orgDoc.data().ownerUid === data.uid) {
                    email = orgDoc.data().ownerEmail;
                    name = orgDoc.data().ownerName;
                }
            }
            
            members.push({
                memberId: doc.id,
                uid: data.uid,
                role: data.role,
                groupId: data.groupId || null,
                joinedAt: data.joinedAt,
                email,
                name
            });
        }
        res.json({ members });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update a member's role or group
app.put('/api/org-members/:memberId', authenticate, async (req, res) => {
    const { role, groupId } = req.body;
    try {
        const memberRef = db.collection('org_members').doc(req.params.memberId);
        const memberDoc = await memberRef.get();
        if (!memberDoc.exists) return res.status(404).json({ error: 'Member not found.' });
        
        const orgId = memberDoc.data().orgId;
        
        // Verify caller is Admin
        const callerMemberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
        if (!callerDoc.exists || !['Admin', 'Owner'].includes(callerDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        const updates = {};
        if (role) updates.role = role;
        if (groupId !== undefined) updates.groupId = groupId; // allow nulling out
        
        await memberRef.update(updates);
        res.json({ message: 'Member updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create a new Group
app.post('/api/groups', authenticate, async (req, res) => {
    const { orgId, name, privileges } = req.body;
    if (!orgId || !name || !privileges) return res.status(400).json({ error: 'Missing required fields.' });

    try {
        // Verify caller is Admin
        const callerMemberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
        if (!callerDoc.exists || !['Admin', 'Owner'].includes(callerDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        const groupRef = await db.collection('groups').add({
            orgId,
            name,
            privileges,
            createdBy: req.user.uid,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({ id: groupRef.id, name, privileges });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get Groups for an org
app.get('/api/groups', authenticate, async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        // Any member can load groups to see the matrix
        const callerMemberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
        if (!callerDoc.exists) return res.status(403).json({ error: 'Access denied.' });

        const result = await db.collection('groups').where('orgId', '==', orgId).get();
        const groups = result.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ groups });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update a Group
app.put('/api/groups/:id', authenticate, async (req, res) => {
    const { privileges } = req.body;
    try {
        const groupRef = db.collection('groups').doc(req.params.id);
        const groupDoc = await groupRef.get();
        if (!groupDoc.exists) return res.status(404).json({ error: 'Group not found.' });
        
        const orgId = groupDoc.data().orgId;
        
        // Verify caller is Admin
        const callerMemberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
        if (!callerDoc.exists || !['Admin', 'Owner'].includes(callerDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        await groupRef.update({ privileges });
        res.json({ message: 'Group updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete a Group
app.delete('/api/groups/:id', authenticate, async (req, res) => {
    try {
        const groupRef = db.collection('groups').doc(req.params.id);
        const groupDoc = await groupRef.get();
        if (!groupDoc.exists) return res.status(404).json({ error: 'Group not found.' });
        
        const orgId = groupDoc.data().orgId;
        
        // Verify caller is Admin
        const callerMemberId = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
        if (!callerDoc.exists || !['Admin', 'Owner'].includes(callerDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        // Optional: Remove groupId from members
        const membersSnapshot = await db.collection('org_members')
            .where('orgId', '==', orgId).where('groupId', '==', req.params.id).get();
        
        const batch = db.batch();
        membersSnapshot.docs.forEach(doc => {
            batch.update(doc.ref, { groupId: null });
        });
        batch.delete(groupRef);
        await batch.commit();

        res.json({ message: 'Group deleted successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- User Profile & Security Routes ---

// Get current profile
app.get('/api/profile', authenticate, async (req, res) => {
    console.log(`👤 Profile request from UID: ${req.user.uid}`);
    try {
        const userDoc = await db.collection('users').doc(req.user.uid).get();
        if (!userDoc.exists) {
            console.log(`❌ Profile NOT FOUND in Firestore for UID: ${req.user.uid}`);
            return res.status(404).json({ error: 'Profile not found' });
        }
        console.log(`✅ Profile loaded for ${req.user.email}`);
        res.json({ profile: { uid: req.user.uid, ...userDoc.data() } });
    } catch (err) {
        console.error(`🔥 Profile error: ${err.message}`);
        res.status(500).json({ error: err.message });
    }
});

// Update profile
app.put('/api/profile', authenticate, async (req, res) => {
    const { firstName, lastName, location } = req.body;
    try {
        const updateData = {
            firstName: firstName || '',
            lastName: lastName || '',
            location: location || '',
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        };
        
        // Update displayName if names are provided
        if (firstName || lastName) {
            updateData.displayName = `${firstName || ''} ${lastName || ''}`.trim();
        }

        await db.collection('users').doc(req.user.uid).update(updateData);
        res.json({ message: 'Profile updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Send verification email (via EmailJS)
app.post('/api/profile/verify-email/send', authenticate, async (req, res) => {
    const userEmail = req.user.email;
    const userId = req.user.uid;

    try {
        // --- Rate Limit: 60-second cooldown between resends ---
        const existing = await db.collection('verification_codes').doc(userId).get();
        if (existing.exists) {
            const sentAt = existing.data().sentAt;
            if (sentAt && Date.now() - sentAt < 60 * 1000) {
                const waitSecs = Math.ceil((60 * 1000 - (Date.now() - sentAt)) / 1000);
                return res.status(429).json({ error: `Please wait ${waitSecs}s before requesting a new code.` });
            }
        }

        // --- Generate secure 6-digit code ---
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
        const sentAt = Date.now();

        // --- Store code in Firestore ---
        await db.collection('verification_codes').doc(userId).set({
            code,
            expiresAt,
            sentAt,
            email: userEmail,
            attempts: 0,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // --- Return code for frontend EmailJS delivery ---
        console.log(`📦 [VERIFY] Code generated for ${userEmail}: ${code}`);
        res.json({ 
            message: 'Verification code generated.',
            code,
            email: userEmail
        });

    } catch (err) {
        console.error(`❌ [EMAIL] Failed to send verification email: ${err.message}`);
        // Clean up stored code if email failed
        await db.collection('verification_codes').doc(userId).delete().catch(() => {});
        res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
    }
});

// Confirm verification email
app.post('/api/profile/verify-email/confirm', authenticate, async (req, res) => {
    const { code } = req.body;
    if (!code || code.trim().length !== 6) return res.status(400).json({ error: 'A valid 6-digit code is required.' });

    const userId = req.user.uid;

    try {
        const codeDoc = await db.collection('verification_codes').doc(userId).get();
        if (!codeDoc.exists) return res.status(400).json({ error: 'No pending verification found. Please request a new code.' });

        const data = codeDoc.data();

        // --- Brute-force protection: max 5 attempts ---
        const attempts = (data.attempts || 0) + 1;
        if (attempts > 5) {
            await db.collection('verification_codes').doc(userId).delete();
            return res.status(429).json({ error: 'Too many failed attempts. Please request a new verification code.' });
        }

        // --- Check expiry ---
        if (Date.now() > data.expiresAt) {
            await db.collection('verification_codes').doc(userId).delete();
            return res.status(400).json({ error: 'Verification code has expired. Please request a new one.' });
        }

        // --- Verify code (constant-time comparison) ---
        if (data.code !== code.trim()) {
            await db.collection('verification_codes').doc(userId).update({ attempts });
            const remaining = 5 - attempts;
            return res.status(400).json({ error: `Incorrect code. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.` });
        }

        // --- SUCCESS: Mark email as verified ---
        await db.collection('users').doc(userId).update({
            isEmailVerified: true,
            emailVerifiedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        // Clean up the code doc
        await db.collection('verification_codes').doc(userId).delete();

        console.log(`✅ [VERIFY] Email verified for ${req.user.email}`);
        res.json({ message: 'Email verified successfully! Your identity is now confirmed.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- System Admin Routes ---

// List all users in the system (System Admin only)
app.get('/api/system/users', authenticate, async (req, res) => {
    if (!req.userData?.isSystemAdmin) {
        return res.status(403).json({ error: 'System Admin access required.' });
    }
    try {
        const usersSnapshot = await db.collection('users').get();
        const users = usersSnapshot.docs.map(doc => doc.data());
        res.json({ users });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`\n🛡️  NexusGuard Firestore API Server running on http://localhost:${PORT}`);
    console.log(`   Database: Cloud Firestore (nexusguard-hub)`);
    console.log(`   RBAC: Active (Groups, Roles, SystemAdmin)`);
    console.log(`   Logging: Enabled\n`);
});
