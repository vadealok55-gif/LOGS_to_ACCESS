// =============================================================
// RBAC Middleware and Utilities for NexusGuard
// All RBAC utilities, middleware functions, and validation logic
// =============================================================

const admin = require('firebase-admin');

// db is lazily referenced so this file can be required before
// Firebase Admin is initialized (server.js initializes admin first).
const getDb = () => admin.firestore();

// ===== ROLE DEFINITIONS =====
const ROLES = {
    OWNER: 'Owner',
    ADMIN: 'Admin',
    MANAGER: 'Manager',
    DEVELOPER: 'Developer',
    VIEWER: 'Viewer'
};

// ===== PRIVILEGES =====
const PRIVILEGES = {
    READ: 'READ',
    WRITE: 'WRITE',
    DELETE: 'DELETE',
    EXECUTE: 'EXECUTE',
    BILLING: 'BILLING',
    NETWORK: 'NETWORK',
    INFRASTRUCTURE: 'INFRASTRUCTURE'
};

// ===== GLOBAL PRIVILEGE MATRIX (ACM Table) =====
// Owner and Admin both have all privileges.
// Manager: READ, WRITE, DELETE.
// Developer: READ, WRITE.
// Viewer: READ only.
const GLOBAL_PRIVILEGES = {
    [ROLES.OWNER]:     [PRIVILEGES.READ, PRIVILEGES.WRITE, PRIVILEGES.DELETE, PRIVILEGES.EXECUTE, PRIVILEGES.BILLING, PRIVILEGES.NETWORK, PRIVILEGES.INFRASTRUCTURE],
    [ROLES.ADMIN]:     [PRIVILEGES.READ, PRIVILEGES.WRITE, PRIVILEGES.DELETE, PRIVILEGES.EXECUTE, PRIVILEGES.BILLING, PRIVILEGES.NETWORK, PRIVILEGES.INFRASTRUCTURE],
    [ROLES.MANAGER]:   [PRIVILEGES.READ, PRIVILEGES.WRITE, PRIVILEGES.DELETE],
    [ROLES.DEVELOPER]: [PRIVILEGES.READ, PRIVILEGES.WRITE],
    [ROLES.VIEWER]:    [PRIVILEGES.READ]
};

// =====================================================================
// HELPER FUNCTIONS (Pure async utilities — not Express middleware)
// =====================================================================

/**
 * Check if a user holds one of the required roles in an organization.
 * Returns { granted: bool, role: string|null, groupId: string|null }
 */
async function checkOrgRole(orgId, uid, requiredRoles) {
    try {
        const db = getDb();
        const memberId = `${orgId}_${uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();

        if (!memberDoc.exists) {
            return { granted: false, role: null, groupId: null };
        }

        const memberData = memberDoc.data();
        const userRole = memberData.role;

        return {
            granted: requiredRoles.includes(userRole),
            role: userRole,
            groupId: memberData.groupId || null
        };
    } catch (error) {
        console.error('[RBAC] Error checking org role:', error);
        return { granted: false, role: null, groupId: null };
    }
}

/**
 * Check if a user has a specific privilege in an org.
 * Checks: SystemAdmin > Owner/Admin implicit > Standard role matrix > Custom group privileges.
 * Returns boolean.
 */
async function checkPrivilege(orgId, uid, privilege, isSystemAdmin = false) {
    if (isSystemAdmin) return true;

    try {
        const db = getDb();
        const memberId = `${orgId}_${uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();

        if (!memberDoc.exists) return false;

        const memberData = memberDoc.data();
        const userRole = memberData.role;

        // Owners and Admins implicitly have all privileges
        if ([ROLES.OWNER, ROLES.ADMIN].includes(userRole)) return true;

        // Check standard role privileges
        const rolePrivileges = GLOBAL_PRIVILEGES[userRole] || [];
        if (rolePrivileges.includes(privilege)) return true;

        // Check custom group privileges
        if (memberData.groupId) {
            const groupDoc = await db.collection('groups').doc(memberData.groupId).get();
            if (groupDoc.exists && groupDoc.data().privileges?.[privilege] === true) {
                return true;
            }
        }

        return false;
    } catch (error) {
        console.error('[RBAC] Error checking privilege:', error);
        return false;
    }
}

/**
 * Full ACM pipeline for resource access.
 * Order: SystemAdmin > Owner/Admin > Group WRITE+allowedGroup > provisionRoles > provisionGroupRoles > DENY
 * Returns { allowed: bool, reason: string }
 */
async function verifyResourceAccess(resourceId, orgId, uid, requiredPrivilege = PRIVILEGES.READ, isSystemAdmin = false) {
    if (isSystemAdmin) return { allowed: true, reason: 'System Admin access' };

    try {
        const db = getDb();

        // Get resource
        const resourceDoc = await db.collection('resources').doc(resourceId).get();
        if (!resourceDoc.exists) return { allowed: false, reason: 'Resource not found' };

        const resource = resourceDoc.data();
        if (resource.orgId !== orgId) return { allowed: false, reason: 'Resource orgId mismatch' };

        // Get member info
        const memberId = `${orgId}_${uid}`;
        const memberDoc = await db.collection('org_members').doc(memberId).get();
        if (!memberDoc.exists) return { allowed: false, reason: 'Not an org member' };

        const memberData = memberDoc.data();

        // Owner/Admin get implicit full access
        if ([ROLES.OWNER, ROLES.ADMIN].includes(memberData.role)) {
            return { allowed: true, reason: 'Owner/Admin access' };
        }

        const hasAllowedGroups = resource.allowedGroups && resource.allowedGroups.length > 0;
        const hasAllowedRoles  = resource.allowedRoles  && resource.allowedRoles.length  > 0;
        const hasProvisionRoles = resource.provisionRoles && Object.keys(resource.provisionRoles).length > 0;
        const hasProvisionGroupRoles = resource.provisionGroupRoles && Object.keys(resource.provisionGroupRoles).length > 0;

        // If no restrictions set at all, fall back to standard role privileges
        if (!hasAllowedGroups && !hasAllowedRoles && !hasProvisionRoles && !hasProvisionGroupRoles) {
            const rolePrivileges = GLOBAL_PRIVILEGES[memberData.role] || [];
            return {
                allowed: rolePrivileges.includes(requiredPrivilege),
                reason: rolePrivileges.includes(requiredPrivilege) ? 'Standard role privilege' : 'Insufficient role privileges'
            };
        }

        // Check group-based access
        if (hasAllowedGroups && memberData.groupId && resource.allowedGroups.includes(memberData.groupId)) {
            return { allowed: true, reason: 'Group in allowedGroups' };
        }

        // Check role-based access
        if (hasAllowedRoles && memberData.role && resource.allowedRoles.includes(memberData.role)) {
            return { allowed: true, reason: 'Role in allowedRoles' };
        }

        // Check user-level provision roles
        if (resource.provisionRoles?.[uid]) {
            const userProvRole = resource.provisionRoles[uid];
            if (
                userProvRole === 'Administration' ||
                (userProvRole === 'Editor' && [PRIVILEGES.WRITE, PRIVILEGES.READ].includes(requiredPrivilege)) ||
                (userProvRole === 'Viewer' && requiredPrivilege === PRIVILEGES.READ)
            ) {
                return { allowed: true, reason: `User provision role: ${userProvRole}` };
            }
        }

        // Check group-level provision roles
        if (memberData.groupId && resource.provisionGroupRoles?.[memberData.groupId]) {
            const groupProvRole = resource.provisionGroupRoles[memberData.groupId];
            if (
                groupProvRole === 'Administration' ||
                (groupProvRole === 'Editor' && [PRIVILEGES.WRITE, PRIVILEGES.READ].includes(requiredPrivilege)) ||
                (groupProvRole === 'Viewer' && requiredPrivilege === PRIVILEGES.READ)
            ) {
                return { allowed: true, reason: `Group provision role: ${groupProvRole}` };
            }
        }

        return { allowed: false, reason: 'No matching access controls' };

    } catch (error) {
        console.error('[RBAC] Error verifying resource access:', error);
        return { allowed: false, reason: 'Access verification error' };
    }
}

// =====================================================================
// EXPRESS MIDDLEWARE FUNCTIONS
// =====================================================================

/**
 * Middleware: Verify user is a System Admin.
 */
function requireSystemAdmin(req, res, next) {
    if (!req.userData?.isSystemAdmin) {
        return res.status(403).json({
            error: 'Access denied. System Administrator privilege required.'
        });
    }
    next();
}

/**
 * Middleware: Verify user has one of the required org roles.
 * Reads orgId from req.query.orgId or req.body.orgId.
 * System Admins always pass.
 */
function requireOrgRole(requiredRoles) {
    return async (req, res, next) => {
        if (req.userData?.isSystemAdmin) return next();

        const orgId = req.query.orgId || req.body.orgId || req.params.orgId;
        if (!orgId) {
            return res.status(400).json({ error: 'orgId is required for this operation' });
        }

        const result = await checkOrgRole(orgId, req.user.uid, requiredRoles);
        req.memberRole = result.role;
        req.memberGroupId = result.groupId;

        if (!result.granted) {
            return res.status(403).json({
                error: `Access denied. Requires one of roles: ${requiredRoles.join(', ')}`,
                currentRole: result.role
            });
        }
        next();
    };
}

/**
 * Middleware: Require Admin or Owner role specifically.
 */
function requireAdminOrOwner(req, res, next) {
    return requireOrgRole([ROLES.OWNER, ROLES.ADMIN])(req, res, next);
}

/**
 * Middleware: Verify user has a specific privilege (via role or custom group).
 * Reads orgId from req.query.orgId or req.body.orgId.
 * System Admins always pass.
 */
function requirePrivilege(privilege) {
    return async (req, res, next) => {
        const orgId = req.query.orgId || req.body.orgId;
        if (!orgId) {
            return res.status(400).json({ error: 'orgId is required for this operation' });
        }

        const granted = await checkPrivilege(orgId, req.user.uid, privilege, req.userData?.isSystemAdmin);

        if (!granted) {
            return res.status(403).json({
                error: `Access denied. Requires ${privilege} privilege.`
            });
        }
        next();
    };
}

// =====================================================================
// VALIDATION FUNCTIONS
// =====================================================================

function validateResourceData(data) {
    const errors = [];
    if (!data.name || data.name.trim().length < 2)  errors.push('Resource name must be at least 2 characters');
    if (!data.type)                                   errors.push('Resource type is required');
    if (!data.orgId)                                  errors.push('orgId is required');
    if (data.allowedGroups && !Array.isArray(data.allowedGroups)) errors.push('allowedGroups must be an array');
    if (data.allowedRoles  && !Array.isArray(data.allowedRoles))  errors.push('allowedRoles must be an array');
    return { isValid: errors.length === 0, errors };
}

function validateOrganizationData(data) {
    const errors = [];
    if (!data.name || data.name.trim().length < 2) errors.push('Organization name must be at least 2 characters');
    return { isValid: errors.length === 0, errors };
}

function validateGroupData(data) {
    const errors = [];
    if (!data.name || data.name.trim().length < 2)    errors.push('Group name must be at least 2 characters');
    if (!data.orgId)                                   errors.push('orgId is required');
    if (!data.privileges || typeof data.privileges !== 'object') errors.push('privileges is required and must be an object');
    return { isValid: errors.length === 0, errors };
}

function validateMemberUpdate(data) {
    const errors = [];
    const validRoles = Object.values(ROLES);
    if (data.role && !validRoles.includes(data.role)) {
        errors.push(`Invalid role. Must be one of: ${validRoles.join(', ')}`);
    }
    return { isValid: errors.length === 0, errors };
}

// ===== EXPORTS =====
module.exports = {
    ROLES,
    PRIVILEGES,
    GLOBAL_PRIVILEGES,
    checkOrgRole,
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
};