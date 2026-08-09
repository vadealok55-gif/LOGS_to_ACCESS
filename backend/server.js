// =============================================================
// NexusGuard — Express API Server
// Main entry point: auth, RBAC, all REST routes, audit logging
// =============================================================

require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const helmet   = require('helmet');
const admin    = require('firebase-admin');
const fs       = require('fs');
const path     = require('path');
const https    = require('https');

// ===== RBAC UTILITIES =====
const {
    ROLES,
    PRIVILEGES,
    checkPrivilege,
    verifyResourceAccess,
    requireSystemAdmin,
    requireOrgRole,
    requireAdminOrOwner,
    requirePrivilege,
    validateResourceData,
    validateOrganizationData,
    validateGroupData,
    validateMemberUpdate
} = require('./rbac-setup');

// ===== STAGING WORKFLOW =====
const { stagingWorkflow, STAGING_STATUS } = require('./staging-workflow');

// =============================================================
// FIREBASE ADMIN SDK INITIALIZATION
// =============================================================
const serviceAccountPath = process.env.GOOGLE_APPLICATION_CREDENTIALS || './serviceAccountKey.json';

try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
        const decodedJson  = Buffer.from(process.env.FIREBASE_SERVICE_ACCOUNT_JSON, 'base64').toString('utf8');
        const serviceAccount = JSON.parse(decodedJson);
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount),
            projectId:  process.env.FIREBASE_PROJECT_ID || 'nexusguard-hub'
        });
        console.log('✅ Firebase Admin initialized from environment variable.');
    } else if (fs.existsSync(serviceAccountPath)) {
        admin.initializeApp({
            credential: admin.credential.cert(require(path.resolve(serviceAccountPath))),
            projectId:  process.env.FIREBASE_PROJECT_ID || 'nexusguard-hub'
        });
        console.log('✅ Firebase Admin initialized from service account file.');
    } else {
        console.warn('⚠️  No credentials found. Running in LIMITED MODE.');
        admin.initializeApp({
            projectId: process.env.FIREBASE_PROJECT_ID || 'nexusguard-hub'
        });
    }
} catch (err) {
    console.error('❌ Firebase Admin Init Error:', err.message);
}

const db = admin.firestore();

// =============================================================
// AUDIT LOGGING
// =============================================================

/**
 * Write an immutable audit log entry to activity_logs.
 * @param {Object} req         - Express request (provides user context, IP)
 * @param {string} action      - Machine-readable action string (e.g. 'RESOURCE_CREATED')
 * @param {Object} details     - Arbitrary detail payload (passwords are masked)
 * @param {string|null} orgId  - Organization context (if known)
 */
const logActivity = async (req, action, details = {}, orgId = null) => {
    try {
        // Mask sensitive fields before writing
        const maskedDetails = { ...details };
        if (maskedDetails.password)           maskedDetails.password           = '********';
        if (maskedDetails.code)               maskedDetails.code               = '******';
        if (maskedDetails.verificationCode)   maskedDetails.verificationCode   = '******';

        const effectiveOrgId = orgId ||
            req.query?.orgId   ||
            req.body?.orgId    ||
            req.params?.orgId  ||
            req.userData?.orgId || null;

        // Build the user display name robustly
        let userName = 'anonymous';
        if (req.userData) {
            userName = req.userData.firstName
                ? `${req.userData.firstName} ${req.userData.lastName || ''}`.trim()
                : (req.userData.displayName || req.userData.userName || req.userData.email || 'anonymous');
        }
        if ((userName === 'anonymous') && req.user?.email) userName = req.user.email;

        const logEntry = {
            uid:       req.user ? req.user.uid   : 'anonymous',
            email:     req.user ? req.user.email : 'anonymous',
            userName,
            action,
            timestamp: admin.firestore.FieldValue.serverTimestamp(),
            details:   maskedDetails,
            ip:        req.headers['x-forwarded-for'] || req.socket?.remoteAddress || req.ip || 'unknown',
            orgId:     effectiveOrgId
        };

        // Dual-identity tag for impersonation sessions
        if (req.realUser) {
            logEntry.impersonatedBy     = req.realUser.uid;
            logEntry.impersonatedByEmail = req.realUser.email;
        }

        await db.collection('activity_logs').add(logEntry);
    } catch (err) {
        console.error(`[LOGGING_ERROR] Action: ${action}, Error: ${err.message}`);
    }
};

// =============================================================
// EXPRESS APP SETUP
// =============================================================
const app  = express();
const PORT = process.env.PORT || 5000;

app.use(cors({
    origin: process.env.CORS_ORIGIN
        ? process.env.CORS_ORIGIN.split(',')
        : ['http://localhost:5173', 'http://localhost:5174', 'http://127.0.0.1:5173', 'http://127.0.0.1:5174', 'http://localhost:3000'],
    credentials: true
}));
app.use(helmet({
    crossOriginOpenerPolicy:   false,
    crossOriginResourcePolicy: false,
    contentSecurityPolicy:     false
}));
app.use(express.json());

// =============================================================
// AUTHENTICATION MIDDLEWARE
// =============================================================

/**
 * Validates the Bearer JWT, populates req.user (decoded token)
 * and req.userData (Firestore user doc). Handles impersonation.
 */
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split('Bearer ')[1];
    try {
        const decoded = await admin.auth().verifyIdToken(token);
        req.user = decoded;

        // Load or auto-create the Firestore user document
        const userRef = db.collection('users').doc(decoded.uid);
        const userDoc = await userRef.get();

        if (userDoc.exists) {
            req.userData = userDoc.data();
        } else {
            const newUser = {
                uid:           decoded.uid,
                email:         decoded.email || '',
                displayName:   decoded.name  || decoded.email || '',
                isSystemAdmin: false,
                isEmailVerified: false,
                createdAt:     admin.firestore.FieldValue.serverTimestamp()
            };
            await userRef.set(newUser);
            req.userData = newUser;
        }

        // Impersonation: only available to System Admins
        const impersonateUid = req.headers['x-impersonate-uid'];
        if (impersonateUid && req.userData?.isSystemAdmin) {
            try {
                const impUserDoc = await db.collection('users').doc(impersonateUid).get();
                if (impUserDoc.exists) {
                    req.realUser = { ...req.user, ...req.userData };   // preserve original admin
                    req.user     = {
                        ...req.user,
                        uid:           impersonateUid,
                        email:         impUserDoc.data().email || '',
                        isImpersonated: true
                    };
                    req.userData = impUserDoc.data();
                    console.log(`🎭 Admin ${req.realUser.email} impersonating ${req.userData.email || impersonateUid}`);
                }
            } catch (impErr) {
                console.error('[IMPERSONATION] Error:', impErr.message);
            }
        }

        next();
    } catch (err) {
        console.error('[AUTH] Token error:', err.message);
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// =============================================================
// AUDIT LOGGER MIDDLEWARE (runs after authenticate)
// =============================================================
const auditLogger = async (req, res, next) => {
    if (req.method === 'GET') return next();

    // Map URL patterns to friendly action names
    let actionName = `${req.method} ${req.originalUrl}`;
    const url = req.originalUrl;

    if      (req.method === 'POST' && url.includes('/resources'))           actionName = 'RESOURCE_CREATED';
    else if (req.method === 'PUT'  && url.includes('/resources') && url.includes('/roles')) actionName = 'PROVISION_ROLE_UPDATED';
    else if (req.method === 'PUT'  && url.includes('/resources'))           actionName = 'RESOURCE_EDITED';
    else if (req.method === 'DELETE' && url.includes('/resources'))         actionName = 'RESOURCE_DELETED';
    else if (req.method === 'POST' && url.includes('/organizations'))       actionName = 'ORG_CREATED';
    else if (req.method === 'PUT'  && url.includes('/organizations'))       actionName = 'ORG_UPDATED';
    else if (req.method === 'DELETE' && url.includes('/organizations'))     actionName = 'ORG_DELETED';
    else if (req.method === 'POST' && url.includes('/groups'))              actionName = 'GROUP_CREATED';
    else if (req.method === 'PUT'  && url.includes('/groups'))              actionName = 'GROUP_UPDATED';
    else if (req.method === 'DELETE' && url.includes('/groups'))            actionName = 'GROUP_DELETED';
    else if (req.method === 'PUT'  && url.includes('/org-members'))         actionName = 'MEMBER_UPDATED';
    else if (req.method === 'POST' && url.includes('/impersonate'))         actionName = 'ADMIN_IMPERSONATION';
    else if (req.method === 'PUT'  && url.includes('/approve'))             actionName = 'JOIN_APPROVED';
    else if (req.method === 'PUT'  && url.includes('/deny'))                actionName = 'JOIN_DENIED';
    else if (req.method === 'DELETE' && url.includes('/join-requests'))     actionName = 'JOIN_REQUEST_CANCELLED';
    else if (req.method === 'POST' && url.includes('/pending-provisions') && url.includes('/approve')) actionName = 'PROVISION_APPROVED';
    else if (req.method === 'POST' && url.includes('/pending-provisions') && url.includes('/deny'))    actionName = 'PROVISION_DENIED';
    else if (req.method === 'POST' && url.includes('/verify-email/send'))   actionName = 'EMAIL_VERIFY_SENT';
    else if (req.method === 'POST' && url.includes('/verify-email/confirm')) actionName = 'EMAIL_VERIFY_CONFIRMED';

    // Fire-and-forget — do not await so it never blocks the route handler
    logActivity(req, actionName, req.body).catch(console.error);
    next();
};

// Apply auth + audit to all /api routes
app.use('/api', authenticate);
app.use('/api', auditLogger);

// =============================================================
// EMAILJS HELPER (server-side delivery)
// =============================================================
const sendEmailJS = (toEmail, code) => {
    return new Promise((resolve, reject) => {
        const payload = {
            service_id:  process.env.EMAILJS_SERVICE_ID,
            template_id: process.env.EMAILJS_TEMPLATE_ID,
            user_id:     process.env.EMAILJS_PUBLIC_KEY,
            template_params: {
                verification_code: code,
                to_email:          toEmail,
                system_name:       'NexusGuard'
            }
        };

        if (process.env.EMAILJS_PRIVATE_KEY) {
            payload.accessToken = process.env.EMAILJS_PRIVATE_KEY;
        }

        const data    = JSON.stringify(payload);
        const options = {
            hostname: 'api.emailjs.com',
            port:     443,
            path:     '/api/v1.0/email/send',
            method:   'POST',
            headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
        };

        console.log(`[EMAILJS] Sending to: ${toEmail}`);

        const req = https.request(options, (res) => {
            let resData = '';
            res.on('data', chunk => resData += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) resolve(resData);
                else reject(new Error(`EmailJS Error ${res.statusCode}: ${resData}`));
            });
        });

        req.on('error', reject);
        req.write(data);
        req.end();
    });
};

// =============================================================
// ── ROUTES ──────────────────────────────────────────────────
// =============================================================

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------
app.get('/api/health', async (req, res) => {
    res.json({
        status:    'ok',
        service:   'NexusGuard API',
        timestamp: new Date().toISOString(),
        database:  'Firestore',
        user:      req.userData
    });
});

// =============================================================
// USER ROUTES
// =============================================================

// Get user's own activity log
app.get('/api/user/activity', async (req, res) => {
    try {
        const uid    = req.user.uid;
        const orgId  = req.query.orgId;

        let query = db.collection('activity_logs').where('uid', '==', uid);
        if (orgId) query = query.where('orgId', '==', orgId);

        const snapshot = await query.get();
        const logs = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                id:        doc.id,
                ...data,
                timestamp: data.timestamp?.toDate ? data.timestamp.toDate().toISOString() : data.timestamp,
                ipAddress: data.ip || 'unknown'
            };
        })
        .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
        .slice(0, 50);

        res.json({ logs });
    } catch (err) {
        console.error('[ACTIVITY]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Explicit login event log
app.post('/api/user/log-login', async (req, res) => {
    try {
        await logActivity(req, 'USER_LOGIN');
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Explicit logout event log
app.post('/api/user/log-logout', async (req, res) => {
    try {
        await logActivity(req, 'USER_LOGOUT');
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get user's organizations
app.get('/api/user/organizations', async (req, res) => {
    try {
        const uid = req.user.uid;
        const memberResult = await db.collection('org_members').where('uid', '==', uid).get();
        const orgIds = memberResult.docs.map(doc => doc.data().orgId);

        if (orgIds.length === 0) return res.json({ organizations: [] });

        // Firestore 'in' supports up to 30 items
        const chunks = [];
        for (let i = 0; i < orgIds.length; i += 30) chunks.push(orgIds.slice(i, i + 30));

        let orgDocs = [];
        for (const chunk of chunks) {
            const result = await db.collection('organizations')
                .where(admin.firestore.FieldPath.documentId(), 'in', chunk).get();
            orgDocs = orgDocs.concat(result.docs);
        }

        const organizations = orgDocs.map(doc => ({
            id:   doc.id,
            ...doc.data(),
            role: memberResult.docs.find(md => md.data().orgId === doc.id)?.data().role || 'Unknown'
        }));

        res.json({ organizations });
    } catch (err) {
        console.error('[USER_ORGS]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// ORGANIZATION ROUTES
// =============================================================

// Create a new organization
app.post('/api/organizations', async (req, res) => {
    const { name } = req.body;
    const ownerUid = req.user.uid;

    const { isValid, errors } = validateOrganizationData({ name });
    if (!isValid) return res.status(400).json({ error: errors.join('; ') });

    try {
        const ownerUserDoc = await db.collection('users').doc(ownerUid).get();
        const ownerName    = ownerUserDoc.exists
            ? (ownerUserDoc.data().displayName || ownerUserDoc.data().email || req.user.email || 'Unknown')
            : (req.user.email || 'Unknown');

        const orgRef = await db.collection('organizations').add({
            name:       name.trim(),
            ownerUid,
            ownerEmail: req.user.email || 'unknown',
            ownerName,
            createdAt:  admin.firestore.FieldValue.serverTimestamp()
        });

        // Creator gets Owner role (full privilege set)
        const memberId = `${orgRef.id}_${ownerUid}`;
        await db.collection('org_members').doc(memberId).set({
            orgId:    orgRef.id,
            uid:      ownerUid,
            email:    req.user.email  || 'unknown',
            name:     ownerName,
            role:     ROLES.OWNER,   // ← FIX: was 'Admin', must be 'Owner'
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        logActivity(req, 'ORG_CREATED', { orgName: name.trim(), orgId: orgRef.id });
        res.status(201).json({ id: orgRef.id, name: name.trim() });
    } catch (err) {
        console.error('[ORG_CREATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get a single organization's detail
app.get('/api/organizations/:orgId', async (req, res) => {
    const { orgId } = req.params;
    try {
        // Must be a member or System Admin
        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists) {
                return res.status(403).json({ error: 'Access denied. Not a member of this organization.' });
            }
        }

        const orgDoc = await db.collection('organizations').doc(orgId).get();
        if (!orgDoc.exists) return res.status(404).json({ error: 'Organization not found.' });

        res.json({ organization: { id: orgDoc.id, ...orgDoc.data() } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update organization name (Owner only)
app.put('/api/organizations/:orgId', async (req, res) => {
    const { orgId }  = req.params;
    const { name }   = req.body;

    if (!name || name.trim().length < 2) {
        return res.status(400).json({ error: 'Organization name must be at least 2 characters.' });
    }

    try {
        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists || memberDoc.data().role !== ROLES.OWNER) {
                return res.status(403).json({ error: 'Only the Owner can rename this organization.' });
            }
        }

        await db.collection('organizations').doc(orgId).update({
            name:      name.trim(),
            updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        logActivity(req, 'ORG_UPDATED', { orgId, newName: name.trim() });
        res.json({ message: 'Organization updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Delete an organization and all its sub-collections (Owner only)
app.delete('/api/organizations/:orgId', async (req, res) => {
    const { orgId } = req.params;
    try {
        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists || memberDoc.data().role !== ROLES.OWNER) {
                return res.status(403).json({ error: 'Only the Owner can delete this organization.' });
            }
        }

        const orgDoc = await db.collection('organizations').doc(orgId).get();
        if (!orgDoc.exists) return res.status(404).json({ error: 'Organization not found.' });

        // Cascade-delete all org sub-documents in a batched write
        const batch = db.batch();

        const collections = [
            db.collection('org_members').where('orgId', '==', orgId),
            db.collection('groups').where('orgId', '==', orgId),
            db.collection('resources').where('orgId', '==', orgId),
            db.collection('pending_provisions').where('orgId', '==', orgId),
            db.collection('join_requests').where('orgId', '==', orgId)
        ];

        for (const query of collections) {
            const snap = await query.get();
            snap.docs.forEach(doc => batch.delete(doc.ref));
        }

        batch.delete(db.collection('organizations').doc(orgId));
        await batch.commit();

        logActivity(req, 'ORG_DELETED', { orgId, orgName: orgDoc.data().name });
        res.json({ message: 'Organization and all associated data deleted.' });
    } catch (err) {
        console.error('[ORG_DELETE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get org-level audit logs (Admin/Owner only)
app.get('/api/organizations/:orgId/audit-logs', async (req, res) => {
    const { orgId } = req.params;
    try {
        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const snapshot = await db.collection('activity_logs').where('orgId', '==', orgId).get();
        const logs = snapshot.docs
            .map(doc => {
                const data = doc.data();
                return {
                    id:        doc.id,
                    ...data,
                    timestamp: data.timestamp?.toDate ? data.timestamp.toDate().toISOString() : data.timestamp,
                    ipAddress: data.ip || 'unknown'
                };
            })
            .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0))
            .slice(0, 200);

        res.json({ logs });
    } catch (err) {
        console.error('[AUDIT_LOGS]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// RESOURCE ROUTES
// =============================================================

// Search resources by name/type/tag (org-scoped)
app.get('/api/resources/search', async (req, res) => {
    const { orgId, q, type } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        const memberId  = `${orgId}_${req.user.uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();
        if (!memberDoc.exists && !req.userData?.isSystemAdmin) {
            return res.status(403).json({ error: 'Access denied. Not an org member.' });
        }

        let query = db.collection('resources').where('orgId', '==', orgId);
        if (type) query = query.where('type', '==', type);

        const snapshot  = await query.get();
        let resources   = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

        // Client-side text filter (Firestore doesn't support full-text search)
        if (q) {
            const qLower = q.toLowerCase();
            resources = resources.filter(r =>
                r.name?.toLowerCase().includes(qLower) ||
                r.type?.toLowerCase().includes(qLower) ||
                (Array.isArray(r.tags) && r.tags.some(t => t.toLowerCase().includes(qLower)))
            );
        }

        res.json({ resources, total: resources.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List resources (org-scoped with ACM filtering, or public)
app.get('/api/resources', async (req, res) => {
    try {
        const { orgId } = req.query;

        if (orgId) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();

            let isAllowedAll = false;
            let userRole     = null;
            let userGroupId  = null;

            if (req.userData?.isSystemAdmin) {
                isAllowedAll = true;
            } else if (memberDoc.exists) {
                const data   = memberDoc.data();
                userRole     = data.role;
                userGroupId  = data.groupId || null;
                isAllowedAll = [ROLES.OWNER, ROLES.ADMIN].includes(userRole);
            } else {
                return res.status(403).json({ error: 'Access denied. Not a member of this organization.' });
            }

            const result    = await db.collection('resources').where('orgId', '==', orgId).get();
            let resources   = result.docs.map(doc => ({ id: doc.id, ...doc.data() }));

            if (!isAllowedAll) {
                resources = resources.filter(r => {
                    const groupsEmpty = !r.allowedGroups || r.allowedGroups.length === 0;
                    const rolesEmpty  = !r.allowedRoles  || r.allowedRoles.length  === 0;
                    const groupAllowed        = !groupsEmpty && userGroupId && r.allowedGroups.includes(userGroupId);
                    const roleAllowed         = !rolesEmpty  && userRole    && r.allowedRoles.includes(userRole);
                    const provisionRoleAllowed      = r.provisionRoles      && r.provisionRoles[req.user.uid];
                    const groupProvisionRoleAllowed = r.provisionGroupRoles && userGroupId && r.provisionGroupRoles[userGroupId];
                    return (groupsEmpty && rolesEmpty) || groupAllowed || roleAllowed || provisionRoleAllowed || groupProvisionRoleAllowed;
                });
            }

            return res.json({ resources, source: 'firestore' });
        } else {
            // Public resources (unauthenticated safe — no org required)
            const result    = await db.collection('resources').where('accessLevel', '==', 'public').get();
            const resources = result.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            return res.json({ resources, source: 'firestore' });
        }
    } catch (err) {
        console.error('[RESOURCES_LIST]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get a single resource with assigned members
app.get('/api/resources/:id/detail', async (req, res) => {
    try {
        const { orgId } = req.query;
        if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

        // Must be an org member
        const memberId  = `${orgId}_${req.user.uid}`;
        const callerDoc = await db.collection('org_members').doc(memberId).get();
        if (!callerDoc.exists && !req.userData?.isSystemAdmin) {
            return res.status(403).json({ error: 'Access denied. Not a member of this organization.' });
        }

        const resourceDoc = await db.collection('resources').doc(req.params.id).get();
        if (!resourceDoc.exists) return res.status(404).json({ error: 'Resource not found.' });

        const resource = { id: resourceDoc.id, ...resourceDoc.data() };

        // Fetch all org members and groups in parallel
        const [membersSnap, groupsSnap] = await Promise.all([
            db.collection('org_members').where('orgId', '==', orgId).get(),
            db.collection('groups').where('orgId', '==', orgId).get()
        ]);

        const groupsById = {};
        groupsSnap.docs.forEach(d => { groupsById[d.id] = d.data().name; });

        let members = membersSnap.docs.map(d => ({ id: d.id, ...d.data() }));

        // Filter members to those with access
        const groupsEmpty = !resource.allowedGroups || resource.allowedGroups.length === 0;
        const rolesEmpty  = !resource.allowedRoles  || resource.allowedRoles.length  === 0;

        if (!groupsEmpty || !rolesEmpty || resource.provisionRoles || resource.provisionGroupRoles) {
            members = members.filter(m => {
                const groupAllowed       = !groupsEmpty && m.groupId && resource.allowedGroups.includes(m.groupId);
                const roleAllowed        = !rolesEmpty  && m.role    && resource.allowedRoles.includes(m.role);
                const provisionAllowed   = resource.provisionRoles      && resource.provisionRoles[m.userId || m.uid];
                const groupProvAllowed   = resource.provisionGroupRoles && m.groupId && resource.provisionGroupRoles[m.groupId];
                return groupAllowed || roleAllowed || provisionAllowed || groupProvAllowed || (groupsEmpty && rolesEmpty);
            });
        }

        // Fetch user profile data for enrichment (use users collection)
        const enriched = await Promise.all(members.map(async m => {
            const userId = m.userId || m.uid;
            let email    = m.email || m.userEmail || '—';
            let name     = m.name  || m.displayName || null;

            if (!name || !email || email === '—') {
                const userDoc = await db.collection('users').doc(userId).get();
                if (userDoc.exists) {
                    const ud = userDoc.data();
                    email = email !== '—' ? email : (ud.email || '—');
                    name  = name  || ud.displayName || ud.firstName
                        ? `${ud.firstName || ''} ${ud.lastName || ''}`.trim() || ud.email
                        : ud.email || 'Unknown';
                }
            }

            const userProvRole  = resource.provisionRoles?.[userId] || null;
            const groupProvRole = resource.provisionGroupRoles?.[m.groupId] || null;

            return {
                uid:                  userId,
                email,
                name:                 name || email,
                role:                 m.role || '—',
                groupId:              m.groupId || null,
                groupName:            m.groupId ? (groupsById[m.groupId] || 'Unknown Group') : '—',
                provisionRole:        userProvRole,
                groupProvisionRole:   groupProvRole,
                effectiveProvisionRole: userProvRole || groupProvRole || null,
                taskTitle:            m.taskTitle  || null,
                taskStatus:           m.taskStatus || null,
                workDetails:          m.workDetails || null,
                joinedAt:             m.joinedAt   || null
            };
        }));

        res.json({ resource, members: enriched });
    } catch (err) {
        console.error('[RESOURCE_DETAIL]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Create a resource (WRITE privilege required, staging for non-admins)
app.post('/api/resources', requirePrivilege(PRIVILEGES.WRITE), async (req, res) => {
    const { name, type, tags, status, traffic, accessLevel, orgId, allowedGroups, allowedRoles } = req.body;

    const { isValid, errors } = validateResourceData({ name, type, orgId });
    if (!isValid) return res.status(400).json({ error: errors.join('; ') });

    try {
        const creatorName  = req.userData?.displayName || req.userData?.email || req.user.email || 'Unknown';
        const resourceData = {
            name:          name.trim(),
            type:          type || 'Folder',
            tags:          tags          || [],
            status:        status        || 'active',
            traffic:       traffic       || '-',
            accessLevel:   accessLevel   || 'private',
            orgId:         orgId         || null,
            creatorUid:    req.user.uid,
            creatorName,
            creatorEmail:  req.user.email || 'unknown',
            allowedGroups: allowedGroups || [],
            allowedRoles:  allowedRoles  || [],
            provisionRoles:      {},
            provisionGroupRoles: {}
        };

        // Determine if this user bypasses staging
        let isAdminOrOwner = !!req.userData?.isSystemAdmin;
        if (!isAdminOrOwner && orgId) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (memberDoc.exists && [ROLES.OWNER, ROLES.ADMIN].includes(memberDoc.data().role)) {
                isAdminOrOwner = true;
            }
        }

        if (isAdminOrOwner) {
            resourceData.logs = [{
                action:    'Created',
                uid:       req.user.uid,
                userName:  creatorName,
                email:     req.user.email || 'unknown',
                details:   `Resource initialized (${type})`,
                storage:   'Firestore',
                timestamp: new Date().toISOString()
            }];
            resourceData.createdAt = admin.firestore.FieldValue.serverTimestamp();
            const docRef = await db.collection('resources').add(resourceData);
            logActivity(req, 'RESOURCE_CREATED', { resourceName: name, orgId });
            return res.status(201).json({ id: docRef.id, ...resourceData, source: 'firestore', staged: false });
        } else {
            // Route to staging area
            resourceData.stagedAt  = admin.firestore.FieldValue.serverTimestamp();
            resourceData.createdAt = admin.firestore.FieldValue.serverTimestamp();
            resourceData.status    = STAGING_STATUS.PENDING;
            const docRef = await db.collection('pending_provisions').add(resourceData);
            logActivity(req, 'PROVISION_STAGED', { resourceName: name, orgId });
            return res.status(202).json({
                id:      docRef.id,
                ...resourceData,
                source:  'staging',
                staged:  true,
                message: 'Provision sent to staging area for admin approval.'
            });
        }
    } catch (err) {
        console.error('[RESOURCE_CREATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Update a resource (ACM pipeline: SystemAdmin > Owner/Admin > Group WRITE > DENY)
app.put('/api/resources/:id', async (req, res) => {
    try {
        const { orgId } = req.body;
        if (!orgId) return res.status(400).json({ error: 'orgId is required for authorization.' });

        const docRef = db.collection('resources').doc(req.params.id);
        const doc    = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Resource not found.' });

        const resourceData = doc.data();
        if (resourceData.orgId !== orgId) return res.status(403).json({ error: 'Org mismatch.' });

        // Run ACM pipeline for WRITE
        const { allowed, reason } = await verifyResourceAccess(
            req.params.id, orgId, req.user.uid, PRIVILEGES.WRITE, req.userData?.isSystemAdmin
        );

        if (!allowed) {
            logActivity(req, 'ACCESS_DENIED', { reason, resourceId: req.params.id, orgId });
            return res.status(403).json({ error: `Access denied: ${reason}` });
        }

        const updates = {};
        const allowed_fields = ['allowedGroups', 'allowedRoles', 'accessLevel', 'name', 'tags', 'type', 'status', 'traffic'];
        allowed_fields.forEach(f => {
            if (req.body[f] !== undefined) updates[f] = req.body[f];
        });

        const changedFields = Object.keys(updates).join(', ') || 'No changes';

        updates.logs = admin.firestore.FieldValue.arrayUnion({
            action:    'Edited',
            uid:       req.user.uid,
            userName:  req.userData?.displayName || req.user.email || 'Unknown',
            email:     req.user.email || 'unknown',
            changes:   changedFields,
            storage:   'Firestore',
            timestamp: new Date().toISOString()
        });

        await docRef.update(updates);
        res.json({ message: 'Resource updated successfully.', source: 'firestore' });
    } catch (err) {
        console.error('[RESOURCE_UPDATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Update resource provision roles (granular per-user/per-group assignments)
app.put('/api/resources/:id/roles', async (req, res) => {
    try {
        const { orgId, targetUid, targetGroupId, newRole } = req.body;

        if (!orgId || (!targetUid && !targetGroupId) || newRole === undefined) {
            return res.status(400).json({ error: 'orgId, (targetUid or targetGroupId), and newRole are required.' });
        }
        if (newRole !== null && !['Administration', 'Editor', 'Viewer'].includes(newRole)) {
            return res.status(400).json({ error: 'Invalid role. Must be Administration, Editor, Viewer, or null (to remove).' });
        }

        const docRef = db.collection('resources').doc(req.params.id);
        const doc    = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Resource not found.' });

        const resourceData = doc.data();
        if (resourceData.orgId !== orgId) return res.status(403).json({ error: 'Org mismatch.' });

        // Authorization check
        let isAuthorized      = false;
        let callerProvisionRole = null;

        if (req.userData?.isSystemAdmin) {
            isAuthorized        = true;
            callerProvisionRole = 'Administration';
        } else {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();

            if (memberDoc.exists) {
                const data = memberDoc.data();
                const callerGroupProvRole = data.groupId
                    ? (resourceData.provisionGroupRoles?.[data.groupId] || null)
                    : null;
                const callerUserProvRole  = resourceData.provisionRoles?.[req.user.uid] || null;
                const effectiveRole       = callerUserProvRole || callerGroupProvRole;

                if ([ROLES.OWNER, ROLES.ADMIN, ROLES.MANAGER].includes(data.role) || resourceData.creatorUid === req.user.uid) {
                    isAuthorized        = true;
                    callerProvisionRole = 'Administration';
                } else if (['Administration', 'Editor'].includes(effectiveRole)) {
                    isAuthorized        = true;
                    callerProvisionRole = effectiveRole;
                }
            }
        }

        if (!isAuthorized) {
            logActivity(req, 'ACCESS_DENIED', { reason: 'Unauthorized provision role edit', resourceId: req.params.id, orgId });
            return res.status(403).json({ error: 'Access denied. Must be an Administrator or Editor of this provision.' });
        }

        // Editor restriction: cannot modify Administration roles
        if (callerProvisionRole === 'Editor') {
            const currentTargetRole = targetGroupId
                ? resourceData.provisionGroupRoles?.[targetGroupId]
                : resourceData.provisionRoles?.[targetUid];
            if (newRole === 'Administration' || currentTargetRole === 'Administration') {
                logActivity(req, 'ACCESS_DENIED', { reason: 'Editor attempted Administration role change', resourceId: req.params.id, orgId });
                return res.status(403).json({ error: 'Editors cannot grant or revoke Administration roles.' });
            }
        }

        const fieldPrefix = targetGroupId ? 'provisionGroupRoles' : 'provisionRoles';
        const targetId    = targetGroupId || targetUid;
        const updates     = {};

        if (newRole === null) {
            updates[`${fieldPrefix}.${targetId}`] = admin.firestore.FieldValue.delete();
        } else {
            updates[`${fieldPrefix}.${targetId}`] = newRole;
        }

        updates.logs = admin.firestore.FieldValue.arrayUnion({
            action:    'Edited',
            uid:       req.user.uid,
            userName:  req.userData?.displayName || req.user.email || 'Unknown',
            email:     req.user.email || 'unknown',
            changes:   `Provision role for ${targetGroupId ? 'group' : 'user'} ${targetId} set to ${newRole || 'None'}`,
            storage:   'Firestore',
            timestamp: new Date().toISOString()
        });

        await docRef.update(updates);
        logActivity(req, 'PROVISION_ROLE_UPDATED', { resourceId: req.params.id, orgId, targetUid, targetGroupId, newRole });
        res.json({ message: 'Provision role updated successfully.', source: 'firestore' });
    } catch (err) {
        console.error('[PROVISION_ROLES]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Delete a resource
app.delete('/api/resources/:id', async (req, res) => {
    try {
        const docRef = db.collection('resources').doc(req.params.id);
        const doc    = await docRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Resource not found.' });

        const resourceData = doc.data();
        const orgId        = resourceData.orgId;

        // Run ACM pipeline for DELETE
        const { allowed, reason } = await verifyResourceAccess(
            req.params.id, orgId, req.user.uid, PRIVILEGES.DELETE, req.userData?.isSystemAdmin
        );

        if (!allowed) {
            logActivity(req, 'ACCESS_DENIED', { reason, resourceId: req.params.id, orgId });
            return res.status(403).json({ error: `Access denied: ${reason}` });
        }

        await docRef.delete();
        logActivity(req, 'RESOURCE_DELETED', { resourceId: req.params.id, resourceName: resourceData.name, orgId });
        res.json({ message: 'Resource deleted.', source: 'firestore' });
    } catch (err) {
        console.error('[RESOURCE_DELETE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// STAGING / PENDING PROVISIONS ROUTES
// =============================================================

// Get all pending provisions for an org (Admin/Owner only)
app.get('/api/pending-provisions', async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        let allowed = !!req.userData?.isSystemAdmin;
        if (!allowed) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            allowed = memberDoc.exists && [ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role);
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        const provisions = await stagingWorkflow.getPendingProvisions(orgId);
        res.json({ provisions });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get staging stats for an org (Admin/Owner only)
app.get('/api/staging/stats/:orgId', async (req, res) => {
    const { orgId } = req.params;
    try {
        let allowed = !!req.userData?.isSystemAdmin;
        if (!allowed) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            allowed = memberDoc.exists && [ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role);
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        const stats = await stagingWorkflow.getStagingStats(orgId);
        res.json({ stats });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve a pending provision
app.post('/api/pending-provisions/:id/approve', async (req, res) => {
    const { id } = req.params;
    const { notes } = req.body;
    try {
        // Get the provision to validate orgId
        const provisionDoc = await db.collection('pending_provisions').doc(id).get();
        if (!provisionDoc.exists) return res.status(404).json({ error: 'Pending provision not found.' });
        const orgId = provisionDoc.data().orgId;

        let allowed = !!req.userData?.isSystemAdmin;
        if (!allowed && orgId) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            allowed = memberDoc.exists && [ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role);
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        const result = await stagingWorkflow.approveProvision(id, req.user.uid, orgId, notes || '');
        logActivity(req, 'PROVISION_APPROVED', { provisionId: id, resourceId: result.resourceId, orgId });
        res.json({ message: 'Provision approved and published.', resourceId: result.resourceId });
    } catch (err) {
        console.error('[PROVISION_APPROVE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Deny / reject a pending provision
app.post('/api/pending-provisions/:id/deny', async (req, res) => {
    const { id } = req.params;
    const { reason } = req.body;
    try {
        const provisionDoc = await db.collection('pending_provisions').doc(id).get();
        if (!provisionDoc.exists) return res.status(404).json({ error: 'Pending provision not found.' });
        const orgId = provisionDoc.data().orgId;

        let allowed = !!req.userData?.isSystemAdmin;
        if (!allowed && orgId) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            allowed = memberDoc.exists && [ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role);
        }
        if (!allowed) return res.status(403).json({ error: 'Admin or Owner access required.' });

        await stagingWorkflow.denyProvision(id, req.user.uid, orgId, reason || '');
        logActivity(req, 'PROVISION_DENIED', { provisionId: id, orgId, reason: reason || 'No reason provided' });
        res.json({ message: 'Provision denied and removed from staging.' });
    } catch (err) {
        console.error('[PROVISION_DENY]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// JOIN REQUEST ROUTES
// =============================================================

// Submit a join request
app.post('/api/join-requests', async (req, res) => {
    const { orgId, requestedRole, workDetails } = req.body;
    const uid = req.user.uid;

    if (!orgId) return res.status(400).json({ error: 'Organization ID is required.' });

    try {
        const orgDoc = await db.collection('organizations').doc(orgId).get();
        if (!orgDoc.exists) return res.status(404).json({ error: 'Organization not found.' });

        // Already a member?
        const memberId      = `${orgId}_${uid}`;
        const existingMember = await db.collection('org_members').doc(memberId).get();
        if (existingMember.exists) return res.status(409).json({ error: 'You are already a member of this organization.' });

        // Already pending?
        const existingReq = await db.collection('join_requests')
            .where('orgId', '==', orgId).where('uid', '==', uid).where('status', '==', 'pending').get();
        if (!existingReq.empty) return res.status(409).json({ error: 'You already have a pending request for this organization.' });

        const validRoles    = [ROLES.MANAGER, ROLES.DEVELOPER, ROLES.VIEWER];
        const finalRole     = validRoles.includes(requestedRole) ? requestedRole : ROLES.VIEWER;

        const reqRef = await db.collection('join_requests').add({
            orgId,
            orgName:       orgDoc.data().name,
            uid,
            email:         req.user.email || req.userData?.email || 'unknown',
            displayName:   req.userData?.displayName || req.user.email || 'User',
            requestedRole: finalRole,
            workDetails:   workDetails || 'No details provided.',
            status:        'pending',
            createdAt:     admin.firestore.FieldValue.serverTimestamp()
        });

        res.status(201).json({ id: reqRef.id, status: 'pending', orgName: orgDoc.data().name });
    } catch (err) {
        console.error('[JOIN_REQUEST_CREATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Get my own join requests
app.get('/api/join-requests/mine', async (req, res) => {
    try {
        const result   = await db.collection('join_requests').where('uid', '==', req.user.uid).get();
        const requests = result.docs
            .map(doc => ({
                id: doc.id,
                ...doc.data(),
                createdAt: doc.data().createdAt?.toDate ? doc.data().createdAt.toDate().toISOString() : doc.data().createdAt
            }))
            .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

        res.json({ requests });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get pending requests for an org (Admin/Owner only)
app.get('/api/join-requests', async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const result   = await db.collection('join_requests')
            .where('orgId', '==', orgId).where('status', '==', 'pending').get();
        const requests = result.docs
            .map(doc => ({
                id: doc.id,
                ...doc.data(),
                createdAt: doc.data().createdAt?.toDate ? doc.data().createdAt.toDate().toISOString() : doc.data().createdAt
            }))
            .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));

        res.json({ requests });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Cancel (delete) own pending join request
app.delete('/api/join-requests/:id', async (req, res) => {
    try {
        const reqDoc = await db.collection('join_requests').doc(req.params.id).get();
        if (!reqDoc.exists) return res.status(404).json({ error: 'Join request not found.' });

        const reqData = reqDoc.data();

        // Only the requester or an Admin/Owner can cancel
        const isSelf = reqData.uid === req.user.uid;
        let isAdmin  = !!req.userData?.isSystemAdmin;

        if (!isSelf && !isAdmin) {
            const memberId  = `${reqData.orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            isAdmin = memberDoc.exists && [ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role);
        }

        if (!isSelf && !isAdmin) {
            return res.status(403).json({ error: 'Access denied. You can only cancel your own requests.' });
        }

        if (reqData.status !== 'pending') {
            return res.status(400).json({ error: `Cannot cancel a request with status: ${reqData.status}` });
        }

        await db.collection('join_requests').doc(req.params.id).update({
            status:     'cancelled',
            cancelledAt: admin.firestore.FieldValue.serverTimestamp()
        });

        logActivity(req, 'JOIN_REQUEST_CANCELLED', { orgId: reqData.orgId, requestId: req.params.id });
        res.json({ message: 'Join request cancelled.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Approve a join request
app.put('/api/join-requests/:id/approve', async (req, res) => {
    try {
        const reqDoc = await db.collection('join_requests').doc(req.params.id).get();
        if (!reqDoc.exists) return res.status(404).json({ error: 'Request not found.' });

        const reqData = reqDoc.data();
        if (reqData.status !== 'pending') return res.status(400).json({ error: 'Request already processed.' });

        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${reqData.orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const validRoles  = Object.values(ROLES);
        const assignedRole = req.body.assignedRole && validRoles.includes(req.body.assignedRole)
            ? req.body.assignedRole
            : (reqData.requestedRole || ROLES.VIEWER);

        const newMemberId = `${reqData.orgId}_${reqData.uid}`;
        await db.collection('org_members').doc(newMemberId).set({
            orgId:    reqData.orgId,
            uid:      reqData.uid,
            email:    reqData.email       || 'unknown',
            name:     reqData.displayName || 'User',
            role:     assignedRole,
            joinedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        await db.collection('join_requests').doc(req.params.id).update({
            status:      'approved',
            reviewedBy:  req.user.uid,
            reviewedAt:  admin.firestore.FieldValue.serverTimestamp(),
            finalRole:   assignedRole
        });

        logActivity(req, 'JOIN_APPROVED', { orgId: reqData.orgId, uid: reqData.uid, assignedRole });
        res.json({ message: 'Request approved.', uid: reqData.uid, email: reqData.email, finalRole: assignedRole });
    } catch (err) {
        console.error('[JOIN_APPROVE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Deny a join request
app.put('/api/join-requests/:id/deny', async (req, res) => {
    try {
        const reqDoc = await db.collection('join_requests').doc(req.params.id).get();
        if (!reqDoc.exists) return res.status(404).json({ error: 'Request not found.' });

        const reqData = reqDoc.data();
        if (reqData.status !== 'pending') return res.status(400).json({ error: 'Request already processed.' });

        if (!req.userData?.isSystemAdmin) {
            const memberId  = `${reqData.orgId}_${req.user.uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();
            if (!memberDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(memberDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        await db.collection('join_requests').doc(req.params.id).update({
            status:     'denied',
            reviewedBy: req.user.uid,
            reviewedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        logActivity(req, 'JOIN_DENIED', { orgId: reqData.orgId, uid: reqData.uid });
        res.json({ message: 'Request denied.', uid: reqData.uid });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// ORG MEMBER MANAGEMENT ROUTES
// =============================================================

// List all members of an org (any member can view)
app.get('/api/org-members', async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists) return res.status(403).json({ error: 'Access denied. Not an org member.' });
        }

        const result  = await db.collection('org_members').where('orgId', '==', orgId).get();
        const members = [];

        // Batch-fetch user profiles from the users collection for accurate info
        const uids = result.docs.map(d => d.data().uid).filter(Boolean);
        const userDocs = {};

        // Chunk UID lookups (max 30 per 'in' query)
        for (let i = 0; i < uids.length; i += 30) {
            const chunk = uids.slice(i, i + 30);
            const usersSnap = await db.collection('users')
                .where(admin.firestore.FieldPath.documentId(), 'in', chunk).get();
            usersSnap.docs.forEach(d => { userDocs[d.id] = d.data(); });
        }

        for (const doc of result.docs) {
            const data     = doc.data();
            const uid      = data.uid;
            const userProfile = userDocs[uid];

            members.push({
                memberId: doc.id,
                uid,
                role:     data.role    || 'Unknown',
                groupId:  data.groupId || null,
                joinedAt: data.joinedAt || null,
                email:    userProfile?.email       || data.email       || 'Unknown',
                name:     userProfile?.displayName || data.name        ||
                          (userProfile?.firstName ? `${userProfile.firstName} ${userProfile.lastName || ''}`.trim() : 'Unknown'),
                taskTitle:   data.taskTitle   || null,
                taskStatus:  data.taskStatus  || null,
                workDetails: data.workDetails || null
            });
        }

        res.json({ members });
    } catch (err) {
        console.error('[ORG_MEMBERS]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Update a member's role or group (Admin/Owner only)
app.put('/api/org-members/:memberId', async (req, res) => {
    const { role, groupId } = req.body;

    const { isValid, errors } = validateMemberUpdate({ role });
    if (!isValid) return res.status(400).json({ error: errors.join('; ') });

    try {
        const memberRef = db.collection('org_members').doc(req.params.memberId);
        const memberDoc = await memberRef.get();
        if (!memberDoc.exists) return res.status(404).json({ error: 'Member not found.' });

        const orgId = memberDoc.data().orgId;

        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(callerDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const updates = {};
        if (role    !== undefined) updates.role    = role;
        if (groupId !== undefined) updates.groupId = groupId || null; // allow nulling out

        await memberRef.update(updates);
        logActivity(req, 'MEMBER_UPDATED', { orgId, memberId: req.params.memberId, updates });
        res.json({ message: 'Member updated successfully.' });
    } catch (err) {
        console.error('[MEMBER_UPDATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Assign or update a task on a member (Admin/Owner only)
app.put('/api/org-members/:memberId/task', async (req, res) => {
    const { taskTitle, taskStatus, workDetails } = req.body;
    try {
        const memberRef = db.collection('org_members').doc(req.params.memberId);
        const memberDoc = await memberRef.get();
        if (!memberDoc.exists) return res.status(404).json({ error: 'Member not found.' });

        const orgId = memberDoc.data().orgId;

        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(callerDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const updates = {};
        if (taskTitle   !== undefined) updates.taskTitle   = taskTitle;
        if (taskStatus  !== undefined) updates.taskStatus  = taskStatus;
        if (workDetails !== undefined) updates.workDetails = workDetails;
        updates.taskUpdatedAt = admin.firestore.FieldValue.serverTimestamp();

        await memberRef.update(updates);
        logActivity(req, 'TASK_ASSIGNED', { orgId, memberId: req.params.memberId, taskTitle });
        res.json({ message: 'Task updated successfully.' });
    } catch (err) {
        console.error('[TASK_ASSIGN]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Complete a task (self or Admin/Owner)
app.put('/api/org-members/:memberId/complete-task', async (req, res) => {
    try {
        const memberRef = db.collection('org_members').doc(req.params.memberId);
        const memberDoc = await memberRef.get();
        if (!memberDoc.exists) return res.status(404).json({ error: 'Member not found.' });

        const memberData = memberDoc.data();
        const orgId      = memberData.orgId;
        const isSelf     = memberData.uid === req.user.uid;

        let canUpdate = isSelf || !!req.userData?.isSystemAdmin;
        if (!canUpdate) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            canUpdate = callerDoc.exists && [ROLES.ADMIN, ROLES.OWNER].includes(callerDoc.data().role);
        }

        if (!canUpdate) {
            return res.status(403).json({ error: 'Unauthorized. You can only complete your own tasks.' });
        }

        await memberRef.update({
            taskStatus:       'done',
            taskCompletedAt:  admin.firestore.FieldValue.serverTimestamp()
        });

        logActivity(req, 'TASK_COMPLETED', {
            memberId:  req.params.memberId,
            taskTitle: memberData.taskTitle || 'Assigned Task',
            orgId
        }, orgId);

        res.json({ success: true, message: 'Task marked as done.' });
    } catch (err) {
        console.error('[TASK_COMPLETE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// GROUP ROUTES
// =============================================================

// Create a group (Admin/Owner only)
app.post('/api/groups', async (req, res) => {
    const { orgId, name, privileges } = req.body;

    const { isValid, errors } = validateGroupData({ orgId, name, privileges });
    if (!isValid) return res.status(400).json({ error: errors.join('; ') });

    try {
        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(callerDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const groupRef = await db.collection('groups').add({
            orgId,
            name:      name.trim(),
            privileges,
            createdBy: req.user.uid,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        logActivity(req, 'GROUP_CREATED', { orgId, groupName: name, groupId: groupRef.id });
        res.status(201).json({ id: groupRef.id, name: name.trim(), privileges });
    } catch (err) {
        console.error('[GROUP_CREATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// List groups for an org (any member)
app.get('/api/groups', async (req, res) => {
    const { orgId } = req.query;
    if (!orgId) return res.status(400).json({ error: 'orgId is required.' });

    try {
        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists) return res.status(403).json({ error: 'Access denied. Not an org member.' });
        }

        const result = await db.collection('groups').where('orgId', '==', orgId).get();
        const groups  = result.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ groups });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update a group's privileges (Admin/Owner only)
app.put('/api/groups/:id', async (req, res) => {
    const { privileges, name } = req.body;
    try {
        const groupRef = db.collection('groups').doc(req.params.id);
        const groupDoc = await groupRef.get();
        if (!groupDoc.exists) return res.status(404).json({ error: 'Group not found.' });

        const orgId = groupDoc.data().orgId;

        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(callerDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        const updates = {};
        if (privileges !== undefined) updates.privileges = privileges;
        if (name       !== undefined) updates.name       = name.trim();
        updates.updatedAt = admin.firestore.FieldValue.serverTimestamp();

        await groupRef.update(updates);
        logActivity(req, 'GROUP_UPDATED', { orgId, groupId: req.params.id });
        res.json({ message: 'Group updated successfully.' });
    } catch (err) {
        console.error('[GROUP_UPDATE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Delete a group and unassign all members (Admin/Owner only)
app.delete('/api/groups/:id', async (req, res) => {
    try {
        const groupRef = db.collection('groups').doc(req.params.id);
        const groupDoc = await groupRef.get();
        if (!groupDoc.exists) return res.status(404).json({ error: 'Group not found.' });

        const orgId     = groupDoc.data().orgId;
        const groupName = groupDoc.data().name;

        if (!req.userData?.isSystemAdmin) {
            const callerMemberId = `${orgId}_${req.user.uid}`;
            const callerDoc      = await db.collection('org_members').doc(callerMemberId).get();
            if (!callerDoc.exists || ![ROLES.ADMIN, ROLES.OWNER].includes(callerDoc.data().role)) {
                return res.status(403).json({ error: 'Admin or Owner access required.' });
            }
        }

        // Remove groupId from all members that were in this group
        const membersSnapshot = await db.collection('org_members')
            .where('orgId', '==', orgId).where('groupId', '==', req.params.id).get();

        const batch = db.batch();
        membersSnapshot.docs.forEach(doc => batch.update(doc.ref, { groupId: null }));
        batch.delete(groupRef);
        await batch.commit();

        logActivity(req, 'GROUP_DELETED', { orgId, groupId: req.params.id, groupName });
        res.json({ message: 'Group deleted successfully.' });
    } catch (err) {
        console.error('[GROUP_DELETE]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// USER PROFILE ROUTES
// =============================================================

// Get current user's profile
app.get('/api/profile', async (req, res) => {
    try {
        const userDoc = await db.collection('users').doc(req.user.uid).get();
        if (!userDoc.exists) return res.status(404).json({ error: 'Profile not found.' });
        res.json({ profile: { uid: req.user.uid, ...userDoc.data() } });
    } catch (err) {
        console.error('[PROFILE_GET]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Update current user's profile
app.put('/api/profile', async (req, res) => {
    const { firstName, lastName, location } = req.body;
    try {
        const updateData = {
            firstName:   firstName || '',
            lastName:    lastName  || '',
            location:    location  || '',
            updatedAt:   admin.firestore.FieldValue.serverTimestamp()
        };
        if (firstName || lastName) {
            updateData.displayName = `${firstName || ''} ${lastName || ''}`.trim();
        }

        await db.collection('users').doc(req.user.uid).update(updateData);
        res.json({ message: 'Profile updated successfully.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Send verification code (generates and returns code for frontend EmailJS delivery)
app.post('/api/profile/verify-email/send', async (req, res) => {
    const userEmail = req.user.email;
    const userId    = req.user.uid;

    if (!userEmail) return res.status(400).json({ error: 'No email address associated with your account.' });

    try {
        // Rate limit: 60-second cooldown
        const existing = await db.collection('verification_codes').doc(userId).get();
        if (existing.exists) {
            const sentAt   = existing.data().sentAt;
            const waitLeft = 60 * 1000 - (Date.now() - sentAt);
            if (waitLeft > 0) {
                return res.status(429).json({ error: `Please wait ${Math.ceil(waitLeft / 1000)}s before requesting a new code.` });
            }
        }

        const code      = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
        const sentAt    = Date.now();

        await db.collection('verification_codes').doc(userId).set({
            code,
            expiresAt,
            sentAt,
            email:     userEmail,
            attempts:  0,
            createdAt: admin.firestore.FieldValue.serverTimestamp()
        });

        console.log(`[VERIFY] Code generated for ${userEmail}`);
        res.json({ message: 'Verification code generated.', code, email: userEmail });
    } catch (err) {
        console.error('[VERIFY_SEND]', err.message);
        await db.collection('verification_codes').doc(userId).delete().catch(() => {});
        res.status(500).json({ error: 'Failed to generate verification code. Please try again.' });
    }
});

// Confirm verification code
app.post('/api/profile/verify-email/confirm', async (req, res) => {
    const { code } = req.body;
    if (!code || code.trim().length !== 6) {
        return res.status(400).json({ error: 'A valid 6-digit code is required.' });
    }

    const userId = req.user.uid;
    try {
        const codeDoc = await db.collection('verification_codes').doc(userId).get();
        if (!codeDoc.exists) {
            return res.status(400).json({ error: 'No pending verification found. Please request a new code.' });
        }

        const data     = codeDoc.data();
        const attempts = (data.attempts || 0) + 1;

        if (attempts > 5) {
            await db.collection('verification_codes').doc(userId).delete();
            return res.status(429).json({ error: 'Too many failed attempts. Please request a new code.' });
        }

        if (Date.now() > data.expiresAt) {
            await db.collection('verification_codes').doc(userId).delete();
            return res.status(400).json({ error: 'Verification code expired. Please request a new one.' });
        }

        if (data.code !== code.trim()) {
            await db.collection('verification_codes').doc(userId).update({ attempts });
            const remaining = 5 - attempts;
            return res.status(400).json({
                error: `Incorrect code. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.`
            });
        }

        // Mark email as verified
        await db.collection('users').doc(userId).update({
            isEmailVerified:  true,
            emailVerifiedAt:  admin.firestore.FieldValue.serverTimestamp()
        });
        await db.collection('verification_codes').doc(userId).delete();

        console.log(`[VERIFY] Email verified for ${req.user.email}`);
        res.json({ message: 'Email verified successfully!' });
    } catch (err) {
        console.error('[VERIFY_CONFIRM]', err.message);
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// SYSTEM ADMIN ROUTES
// =============================================================

// List all users (System Admin only)
app.get('/api/system/users', requireSystemAdmin, async (req, res) => {
    try {
        const usersSnapshot = await db.collection('users').get();
        const users = usersSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ users, total: users.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// List all organizations (System Admin only)
app.get('/api/system/organizations', requireSystemAdmin, async (req, res) => {
    try {
        const orgsSnapshot = await db.collection('organizations').get();
        const organizations = orgsSnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        res.json({ organizations, total: organizations.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Promote/demote System Admin flag (System Admin only)
app.put('/api/system/users/:uid/admin', requireSystemAdmin, async (req, res) => {
    const { uid } = req.params;
    const { isSystemAdmin } = req.body;

    if (typeof isSystemAdmin !== 'boolean') {
        return res.status(400).json({ error: 'isSystemAdmin must be a boolean.' });
    }

    // Prevent self-demotion to avoid lockout
    if (uid === req.user.uid && !isSystemAdmin) {
        return res.status(400).json({ error: 'You cannot revoke your own System Admin privilege.' });
    }

    try {
        const userRef = db.collection('users').doc(uid);
        const userDoc = await userRef.get();
        if (!userDoc.exists) return res.status(404).json({ error: 'User not found.' });

        await userRef.update({ isSystemAdmin });
        logActivity(req, 'SYSTEM_ADMIN_UPDATED', { targetUid: uid, isSystemAdmin });
        res.json({ message: `User ${isSystemAdmin ? 'promoted to' : 'demoted from'} System Admin.` });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// =============================================================
// GLOBAL ERROR HANDLER
// =============================================================
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    console.error('[UNHANDLED_ERROR]', err.stack || err.message);
    res.status(err.status || 500).json({
        error: err.message || 'An unexpected server error occurred.',
        code:  err.code    || 'INTERNAL_SERVER_ERROR'
    });
});

// 404 catch-all
app.use((req, res) => {
    res.status(404).json({ error: `Route not found: ${req.method} ${req.originalUrl}` });
});

// =============================================================
// START SERVER
// =============================================================
app.listen(PORT, () => {
    console.log(`\n🛡️  NexusGuard API running on http://localhost:${PORT}`);
    console.log(`   Database:  Cloud Firestore`);
    console.log(`   RBAC:      Active (Groups, Roles, SystemAdmin, ACM)`);
    console.log(`   Staging:   Active (Maker-Checker workflow)`);
    console.log(`   Logging:   Enabled (Immutable audit trail)\n`);
});
