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
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        // Option 1: Parse from environment variable string (Best for Render/Heroku)
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId: process.env.FIREBASE_PROJECT_ID || 'nexusguard-hub'
        });
        console.log('✅ Firebase Admin initialized with service account from Environment Variable.');
    } else if (fs.existsSync(serviceAccountPath)) {
        // Option 2: Read from local file (Best for local dev)
        admin.initializeApp({
            credential: admin.credential.cert(require(path.resolve(serviceAccountPath))),
            projectId: process.env.FIREBASE_PROJECT_ID || 'nexusguard-hub'
        });
        console.log('✅ Firebase Admin initialized with service account file.');
    } else {
        console.warn('⚠️  serviceAccountKey.json not found and FIREBASE_SERVICE_ACCOUNT_JSON not set. Backend will run in LIMITED MODE (RBAC & Firestore will fail).');
        console.warn('👉 Provide credentials via environment variables for production deployments.');
        admin.initializeApp({
            projectId: process.env.FIREBASE_PROJECT_ID || 'nexusguard-hub'
        });

    }
} catch (err) {
    console.error('❌ Firebase Admin Init Error:', err.message);
}

const db = admin.firestore();
const logActivity = async (req, action, details = {}, orgId = null) => {
    try {
        // Mask passwords and codes in a local copy
        const maskedDetails = { ...details };
        if (maskedDetails.password) maskedDetails.password = '********';
        if (maskedDetails.code) maskedDetails.code = '******';
        if (maskedDetails.verificationCode) maskedDetails.verificationCode = '******';

        // Robustly get orgId from various sources
        const effectiveOrgId = orgId || 
                              req.query?.orgId || 
                              req.body?.orgId || 
                              req.params?.orgId || 
                              req.userData?.orgId || null;

        const logEntry = {
            uid: req.user ? req.user.uid : 'anonymous',
            email: req.user ? req.user.email : 'anonymous',
            userName: req.userData ? (req.userData.firstName ? `${req.userData.firstName} ${req.userData.lastName || ''}`.trim() : (req.userData.displayName || req.userData.userName || req.userData.email)) : (req.user ? req.user.email : 'anonymous'),
            action,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            details: maskedDetails,
            ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress || req.ip || 'unknown',
            orgId: effectiveOrgId
        };
        
        // Final fallback for userName
        if ((!logEntry.userName || logEntry.userName === 'anonymous') && req.user?.email) {
            logEntry.userName = req.user.email;
        }

        await db.collection('activity_logs').add(logEntry);
    } catch (err) {
        console.error(`[LOGGING_ERROR] Action: ${action}, Error:`, err.message);
    }
};




const app = express();
const PORT = process.env.PORT || 5000;

// --- Middleware ---
app.use(cors({
    origin: process.env.CORS_ORIGIN || ['http://localhost:5173', 'http://localhost:5174', 'http://127.0.0.1:5173', 'http://127.0.0.1:5174', 'http://localhost:3000'],
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
        let actionName = `${req.method} ${req.originalUrl}`;
        
        // Map to friendly names for UI
        if (req.method === 'POST' && req.originalUrl.includes('/resources')) actionName = 'RESOURCE_CREATED';
        else if (req.method === 'PUT' && req.originalUrl.includes('/resources')) actionName = 'RESOURCE_EDITED';
        else if (req.method === 'POST' && req.originalUrl.includes('/organizations')) actionName = 'ORG_CREATED';
        else if (req.method === 'POST' && req.originalUrl.includes('/groups')) actionName = 'GROUP_CREATED';
        else if (req.method === 'PUT' && req.originalUrl.includes('/groups')) actionName = 'GROUP_UPDATED';
        else if (req.method === 'PUT' && req.originalUrl.includes('/members')) actionName = 'USER_ROLE_UPDATED';
        else if (req.method === 'POST' && req.originalUrl.includes('/impersonate')) actionName = 'ADMIN_IMPERSONATION';
        else if (req.method === 'PUT' && req.originalUrl.includes('/approve')) actionName = 'JOIN_APPROVED';
        else if (req.method === 'PUT' && req.originalUrl.includes('/deny')) actionName = 'JOIN_DENIED';

        // Note: req.user/req.userData might not be populated if logger runs before authenticate.
        // We will call logActivity, which handles anonymous cases.
        logActivity(req, actionName, req.body);
    }
    next();
};

app.use('/api', authenticate);
app.use(logger);

// RBAC: Check if System Admin
const isSystemAdmin = (req, res, next) => {
    if (req.userData && req.userData.isSystemAdmin) {
        next();
    } else {
        logActivity(req, 'ACCESS_DENIED', { reason: 'System Administrator privilege required', url: req.originalUrl });
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
                logActivity(req, 'ACCESS_DENIED', { reason: `Required roles: ${roles.join(', ')}`, orgId });
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

            if (!memberDoc.exists) {
                logActivity(req, 'ACCESS_DENIED', { reason: 'Not an org member', orgId });
                return res.status(403).json({ error: 'Access denied.' });
            }

            const data = memberDoc.data();
            
            // Owners and Admins implicitly have all privileges
            if (['Owner', 'Admin'].includes(data.role)) return next();

            // Built-in standard roles have implicit privileges
            const standardPrivileges = {
                'Manager': ['READ', 'WRITE', 'DELETE'],
                'Developer': ['READ', 'WRITE'],
                'Viewer': ['READ']
            };

            if (standardPrivileges[data.role] && standardPrivileges[data.role].includes(privilege)) {
                return next();
            }

            // Check custom group privilege
            if (data.groupId) {
                const groupDoc = await db.collection('groups').doc(data.groupId).get();
                if (groupDoc.exists && groupDoc.data().privileges?.[privilege]) {
                    return next();
                }
            }
            
            logActivity(req, 'ACCESS_DENIED', { reason: `Requires ${privilege} privilege`, orgId });
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
        const { orgId } = req.query;

        let query = db.collection('activity_logs').where('uid', '==', uid);
        if (orgId) {
            query = query.where('orgId', '==', orgId);
        }

        const snapshot = await query.get();
        
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
        await logActivity(req, 'USER_LOGIN');
        res.json({ success: true });
    } catch (err) {
        console.error('Log login error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Explicit endpoint to log logout
app.post('/api/user/log-logout', authenticate, async (req, res) => {
    try {
        await logActivity(req, 'USER_LOGOUT');
        res.json({ success: true });
    } catch (err) {
        console.error('Log logout error:', err.message);
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

            // Filter resources based on allowedGroups, allowedRoles, and provisionRoles
            if (!isAllowedAll) {
                resources = resources.filter(resourceData => {
                    const groupsEmpty = !resourceData.allowedGroups || resourceData.allowedGroups.length === 0;
                    const rolesEmpty = !resourceData.allowedRoles || resourceData.allowedRoles.length === 0;
                    
                    const groupAllowed = !groupsEmpty && userGroupId && resourceData.allowedGroups.includes(userGroupId);
                    const roleAllowed = !rolesEmpty && userRole && resourceData.allowedRoles.includes(userRole);
                    const provisionRoleAllowed = resourceData.provisionRoles && resourceData.provisionRoles[req.user.uid];
                    const groupRoleAllowed = resourceData.provisionGroupRoles && userGroupId && resourceData.provisionGroupRoles[userGroupId];

                    return (groupsEmpty && rolesEmpty) || groupAllowed || roleAllowed || provisionRoleAllowed || groupRoleAllowed;
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
        if (!groupsEmpty || !rolesEmpty || resource.provisionRoles) {
            members = members.filter(m => {
                const groupAllowed = !groupsEmpty && m.groupId && resource.allowedGroups.includes(m.groupId);
                const roleAllowed = !rolesEmpty && m.role && resource.allowedRoles.includes(m.role);
                const provisionRoleAllowed = resource.provisionRoles && resource.provisionRoles[m.userId];
                const groupProvisionRoleAllowed = resource.provisionGroupRoles && m.groupId && resource.provisionGroupRoles[m.groupId];
                return groupAllowed || roleAllowed || provisionRoleAllowed || groupProvisionRoleAllowed || (groupsEmpty && rolesEmpty);
            });
        }

        // Enrich with group name and task assignment
        const enriched = members.map(m => {
            const userProvRole = resource.provisionRoles?.[m.userId] || null;
            const groupProvRole = resource.provisionGroupRoles?.[m.groupId] || null;
            
            return {
                uid: m.userId,
                email: m.email || m.userEmail || '—',
                role: m.role || '—',
                provisionRole: userProvRole,
                groupProvisionRole: groupProvRole,
                effectiveProvisionRole: userProvRole || groupProvRole || null,
                groupId: m.groupId || null,
                groupName: m.groupId ? (groupsById[m.groupId] || 'Unknown Group') : '—',
                taskTitle: m.taskTitle || null,
                taskStatus: m.taskStatus || null,
                workDetails: m.workDetails || null,
                joinedAt: m.joinedAt || null
            };
        });

        res.json({ resource, members: enriched });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create a resource
app.post('/api/resources', authenticate, hasPrivilege('WRITE'), async (req, res) => {
    const { name, type, tags, status, traffic, accessLevel, orgId, allowedGroups, allowedRoles } = req.body;
    try {
        // Determine if the user is an Admin or Owner — they bypass staging
        let isAdminOrOwner = false;
        if (req.userData?.isSystemAdmin) {
            isAdminOrOwner = true;
        } else if (orgId) {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists && ['Owner', 'Admin'].includes(memberDoc.data().role)) {
                isAdminOrOwner = true;
            }
        }

        const creatorName = req.userData?.displayName || req.userData?.email || req.user.email || 'Unknown';
        const resourceData = {
            name,
            type: type || 'Folder',
            tags: tags || [],
            status: status || 'active',
            traffic: traffic || '-',
            accessLevel: accessLevel || 'private',
            orgId: orgId || null,
            creatorUid: req.user.uid,
            creatorName,
            creatorEmail: req.user.email || 'unknown',
            allowedGroups: allowedGroups || [],
            allowedRoles: allowedRoles || [],
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        };

        if (isAdminOrOwner) {
            // Publish directly to the resource hub
            resourceData.logs = [{
                action: 'Created',
                uid: req.user.uid,
                userName: creatorName,
                email: req.user.email || 'unknown',
                details: `Resource initialized (${type})`,
                storage: 'Firestore',
                timestamp: new Date().toISOString()
            }];
            const docRef = await db.collection('resources').add(resourceData);
            logActivity(req, 'RESOURCE_CREATED', { resourceName: name, orgId });
            return res.status(201).json({ id: docRef.id, ...resourceData, source: 'firestore', staged: false });
        } else {
            // Route to staging area for approval
            resourceData.stagedAt = admin.firestore.FieldValue.serverTimestamp();
            const docRef = await db.collection('pending_provisions').add(resourceData);
            logActivity(req, 'PROVISION_STAGED', { resourceName: name, orgId });
            return res.status(202).json({ id: docRef.id, ...resourceData, source: 'staging', staged: true, message: 'Provision sent to staging area for admin approval.' });
        }
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

        if (!canEdit) {
            logActivity(req, 'ACCESS_DENIED', { reason: 'Resource write permission denied', resourceId: req.params.id, orgId });
            return res.status(403).json({ error: 'Access denied. Setup custom groups or verify WRITE permissions.' });
        }

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

// Update resource provision roles (granular permissions)
app.put('/api/resources/:id/roles', authenticate, async (req, res) => {
    try {
        const { orgId, targetUid, targetGroupId, newRole } = req.body;
        if (!orgId || (!targetUid && !targetGroupId) || newRole === undefined) {
            return res.status(400).json({ error: 'orgId, (targetUid or targetGroupId), and newRole are required' });
        }
        
        // validate newRole
        if (newRole !== null && !['Administration', 'Editor', 'Viewer'].includes(newRole)) {
            return res.status(400).json({ error: 'Invalid role. Must be Administration, Editor, Viewer, or null (to remove)' });
        }

        const docRef = db.collection('resources').doc(req.params.id);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Resource not found' });
        
        const resourceData = doc.data();
        if (resourceData.orgId !== orgId) return res.status(403).json({ error: 'Org mismatch' });

        // Authorization Check
        let callerProvisionRole = resourceData.provisionRoles?.[req.user.uid];
        let isAuthorized = false;

        if (req.userData.isSystemAdmin) {
            isAuthorized = true;
            callerProvisionRole = 'Administration'; // override for logic
        } else {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists) {
                const data = memberDoc.data();
                
                // Get caller's group provision role if any
                const callerGroupProvRole = data.groupId ? (resourceData.provisionGroupRoles?.[data.groupId] || null) : null;
                
                // Effective role logic
                const effectiveCallerRole = callerProvisionRole || callerGroupProvRole;

                if (['Owner', 'Admin', 'Manager'].includes(data.role) || resourceData.creatorUid === req.user.uid) {
                    isAuthorized = true;
                    callerProvisionRole = 'Administration'; // implicit highest role
                } else if (effectiveCallerRole === 'Administration' || effectiveCallerRole === 'Editor') {
                    isAuthorized = true;
                    // For logic below, we need the effective one
                    callerProvisionRole = effectiveCallerRole;
                }
            }
        }

        if (!isAuthorized) {
            logActivity(req, 'ACCESS_DENIED', { reason: 'Unauthorized attempt to modify provision roles', resourceId: req.params.id, orgId });
            return res.status(403).json({ error: 'Access denied. You must be an Administrator or Editor of this provision.' });
        }

        // Editor Role Restrictions
        const currentTargetRole = targetGroupId 
            ? resourceData.provisionGroupRoles?.[targetGroupId] 
            : resourceData.provisionRoles?.[targetUid];

        if (callerProvisionRole === 'Editor') {
            if (newRole === 'Administration' || currentTargetRole === 'Administration') {
                logActivity(req, 'ACCESS_DENIED', { reason: 'Editor attempted to modify Administration role', resourceId: req.params.id, orgId, targetUid, targetGroupId });
                return res.status(403).json({ error: 'Editors cannot grant or revoke Administration roles.' });
            }
        }

        // Update the provisionRoles or provisionGroupRoles map
        const updates = {};
        const fieldPrefix = targetGroupId ? 'provisionGroupRoles' : 'provisionRoles';
        const targetId = targetGroupId || targetUid;

        if (newRole === null) {
            updates[`${fieldPrefix}.${targetId}`] = admin.firestore.FieldValue.delete();
        } else {
            updates[`${fieldPrefix}.${targetId}`] = newRole;
        }

        updates.logs = admin.firestore.FieldValue.arrayUnion({
            action: 'Edited',
            uid: req.user.uid,
            userName: req.userData?.displayName || req.userData?.email || req.user.email || 'Unknown',
            email: req.user.email || 'unknown',
            changes: `Provision Role updated for ${targetGroupId ? 'group' : 'user'} ${targetId} to ${newRole || 'None'}`,
            storage: 'Firestore',
            timestamp: new Date().toISOString()
        });

        await docRef.update(updates);
        logActivity(req, 'PROVISION_ROLE_UPDATED', { resourceId: req.params.id, orgId, targetUid, targetGroupId, newRole });
        res.json({ message: 'Provision role updated successfully', source: 'firestore' });
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

        if (!canEdit) {
            logActivity(req, 'ACCESS_DENIED', { reason: 'Resource delete permission denied', resourceId: req.params.id, orgId });
            return res.status(403).json({ error: 'Access denied. You do not have permission to delete this resource.' });
        }

        await docRef.delete();
        res.json({ message: 'Deleted', source: 'firestore' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ---- Staging Area / Pending Provisions ----

// Get all pending provisions for an org (Admin/Owner only)
app.get('/api/pending-provisions', authenticate, async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required' });
    try {
        // Verify Admin/Owner
        let allowed = false;
        if (req.userData?.isSystemAdmin) {
            allowed = true;
        } else {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists && ['Admin', 'Owner'].includes(memberDoc.data().role)) {
                allowed = true;
            }
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        const snapshot = await db.collection('pending_provisions').where('orgId', '==', orgId).get();
        const provisions = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id: doc.id,
                ...data,
                stagedAt: data.stagedAt?.toDate ? data.stagedAt.toDate().toISOString() : data.stagedAt,
                createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : data.createdAt,
            };
        }).sort((a, b) => new Date(b.stagedAt) - new Date(a.stagedAt));

        res.json({ provisions });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve a pending provision — move it to the resources collection
app.post('/api/pending-provisions/:id/approve', authenticate, async (req, res) => {
    const { id } = req.params;
    try {
        const docRef = db.collection('pending_provisions').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Pending provision not found.' });

        const data = doc.data();
        const orgId = data.orgId;

        // Verify Admin/Owner
        let allowed = false;
        if (req.userData?.isSystemAdmin) {
            allowed = true;
        } else if (orgId) {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists && ['Admin', 'Owner'].includes(memberDoc.data().role)) {
                allowed = true;
            }
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        const approverName = req.userData?.displayName || req.userData?.email || req.user.email || 'Unknown';

        // Move to resources collection
        const resourceData = {
            ...data,
            logs: [{
                action: 'Created',
                uid: data.creatorUid,
                userName: data.creatorName || 'Unknown',
                email: data.creatorEmail || 'unknown',
                details: `Provision approved by ${approverName}`,
                storage: 'Firestore',
                timestamp: new Date().toISOString()
            }],
            approvedBy: req.user.uid,
            approvedByName: approverName,
            approvedAt: admin.firestore.FieldValue.serverTimestamp(),
        };
        // Remove staging-specific fields
        delete resourceData.stagedAt;

        const newRef = await db.collection('resources').add(resourceData);
        await docRef.delete();
        logActivity(req, 'PROVISION_APPROVED', { provisionId: id, resourceName: data.name, orgId });
        res.json({ message: 'Provision approved and published.', resourceId: newRef.id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Deny / reject a pending provision — remove it from staging
app.post('/api/pending-provisions/:id/deny', authenticate, async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    try {
        const docRef = db.collection('pending_provisions').doc(id);
        const doc = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Pending provision not found.' });

        const data = doc.data();
        const orgId = data.orgId;

        // Verify Admin/Owner
        let allowed = false;
        if (req.userData?.isSystemAdmin) {
            allowed = true;
        } else if (orgId) {
            const memberId = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists && ['Admin', 'Owner'].includes(memberDoc.data().role)) {
                allowed = true;
            }
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        await docRef.delete();
        logActivity(req, 'PROVISION_DENIED', { provisionId: id, resourceName: data.name, orgId, reason: reason || 'No reason provided' });
        res.json({ message: 'Provision denied and removed from staging.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.get('/api/organizations/:orgId/audit-logs', authenticate, async (req, res) => {
    const { orgId } = req.params;
    try {
        // Verify caller is Admin or Owner of the org
        const memberId = `${orgId}_${req.user.uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();
        if (!memberDoc.exists || !['Admin', 'Owner'].includes(memberDoc.data().role)) {
            return res.status(403).json({ error: 'Admin access required.' });
        }

        const snapshot = await db.collection('activity_logs')
            .where('orgId', '==', orgId)
            .get();
        
        const logs = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id: doc.id,
                ...data,
                timestamp: data.timestamp?.toDate ? data.timestamp.toDate().toISOString() : data.timestamp,
                ipAddress: data.ip || 'unknown'
            };
        })
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 100);
        
        res.json({ logs });
    } catch (err) {
        console.error('Fetch org audit logs error:', err.message);
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

// Mark a task as complete
app.put('/api/org-members/:memberId/complete-task', authenticate, async (req, res) => {
    try {
        const memberRef = db.collection('org_members').doc(req.params.memberId);
        const memberDoc = await memberRef.get();
        if (!memberDoc.exists) return res.status(404).json({ error: 'Member not found.' });
        
        const memberData = memberDoc.data();
        const orgId = memberData.orgId;
        
        // Security check: Either you are completing your own task, or you are an admin/owner
        const isSelf = memberData.uid === req.user.uid;
        let canUpdate = isSelf;
        
        if (!canUpdate) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc = await db.collection('org_members').doc(callerMemberId).get();
            if (callerDoc.exists && ['Admin', 'Owner'].includes(callerDoc.data().role)) {
                canUpdate = true;
            }
        }

        if (!canUpdate) {
            await logActivity(req, 'ACCESS_DENIED', { 
                targetMemberId: req.params.memberId, 
                reason: 'Unauthorized task completion attempt' 
            }, orgId);
            return res.status(403).json({ error: 'Unauthorized. You can only complete your own tasks unless you are an admin.' });
        }

        await memberRef.update({
            taskStatus: 'done',
            taskCompletedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await logActivity(req, 'TASK_COMPLETED', {
            memberId: req.params.memberId,
            taskTitle: memberData.taskTitle || 'Assigned Task',
            userName: memberData.userName || memberData.email
        }, orgId);

        res.json({ success: true, message: 'Task marked as done.' });
    } catch (err) {
        console.error('Complete task error:', err.message);
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
