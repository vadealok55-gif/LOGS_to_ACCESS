// =============================================================
// Staging Workflow Implementation for NexusGuard
// Complete approval workflow system for resource provisioning
// =============================================================

const admin = require('firebase-admin');

// Lazy db accessor to avoid initialization-order issues
const getDb = () => admin.firestore();

// ===== STAGING WORKFLOW CONSTANTS =====
const STAGING_STATUS = {
    PENDING:  'pending_approval',
    APPROVED: 'approved',
    DENIED:   'denied'
};

const PROVISION_STATUS = {
    ACTIVE:   'active',
    INACTIVE: 'inactive',
    ARCHIVED: 'archived'
};

// Local role constants (mirrors rbac-setup.js to avoid circular deps)
const ROLES = {
    OWNER:     'Owner',
    ADMIN:     'Admin',
    MANAGER:   'Manager',
    DEVELOPER: 'Developer',
    VIEWER:    'Viewer'
};

// ===== STAGING WORKFLOW CLASS =====
class StagingWorkflow {

    // ===== CORE WORKFLOW METHODS =====

    /**
     * Route a resource creation request through the staging pipeline.
     * Admins/Owners publish directly; everyone else goes to staging.
     */
    async createProvision(orgId, uid, resourceData) {
        const db = getDb();
        try {
            const memberId = `${orgId}_${uid}`;
            const memberDoc = await db.collection('org_members').doc(memberId).get();

            if (!memberDoc.exists) {
                throw new Error('User is not a member of the organization');
            }

            const memberData = memberDoc.data();

            // Admins/Owners bypass staging and publish directly
            if ([ROLES.OWNER, ROLES.ADMIN].includes(memberData.role)) {
                return await this.createDirectProvision(orgId, uid, resourceData);
            }

            // Everyone else → staging queue
            const provisionId = await this.createStagingProvision(orgId, uid, resourceData);

            await this.logActivity(uid, 'PROVISION_STAGED', {
                provisionId,
                orgId,
                resourceName: resourceData.name,
                reason: 'Non-admin user provision requires approval'
            }, orgId);

            return {
                success:     true,
                provisionId,
                status:      STAGING_STATUS.PENDING,
                staged:      true,
                message:     'Provision sent to staging area for admin approval'
            };

        } catch (error) {
            console.error('[STAGING] Error creating provision:', error);
            throw error;
        }
    }

    /**
     * Publish a resource directly to the live resources collection (Admin/Owner path).
     */
    async createDirectProvision(orgId, uid, resourceData) {
        const db = getDb();
        try {
            const validatedResource = {
                ...resourceData,
                orgId,
                creatorUid: uid,
                status:     PROVISION_STATUS.ACTIVE,
                createdAt:  admin.firestore.FieldValue.serverTimestamp(),
                logs: [{
                    action:    'Created',
                    uid,
                    userName:  resourceData.creatorName  || 'Unknown',
                    email:     resourceData.creatorEmail || 'unknown',
                    details:   `Resource initialized (${resourceData.type})`,
                    storage:   'Firestore',
                    timestamp: new Date().toISOString()
                }]
            };

            const docRef = await db.collection('resources').add(validatedResource);

            await this.logActivity(uid, 'RESOURCE_CREATED', {
                resourceId:   docRef.id,
                orgId,
                resourceName: resourceData.name
            }, orgId);

            return {
                success:    true,
                resourceId: docRef.id,
                status:     PROVISION_STATUS.ACTIVE,
                staged:     false,
                message:    'Resource created successfully'
            };

        } catch (error) {
            console.error('[STAGING] Error creating direct provision:', error);
            throw error;
        }
    }

    /**
     * Place a non-admin resource request in the pending_provisions collection.
     */
    async createStagingProvision(orgId, uid, resourceData) {
        const db = getDb();
        try {
            // Look up the user's display info
            const userDoc = await db.collection('users').doc(uid).get();
            if (!userDoc.exists) {
                throw new Error('User not found in users collection');
            }

            const userData = userDoc.data();

            // Fetch admin/owner UIDs so the UI can notify them
            const adminUids = await this.getAdminOrOwnerUids(orgId);

            const provisionData = {
                ...resourceData,
                orgId,
                creatorUid:          uid,
                creatorName:         userData.displayName || userData.email || 'Unknown',
                creatorEmail:        userData.email || 'unknown',
                status:              STAGING_STATUS.PENDING,
                stagedAt:            admin.firestore.FieldValue.serverTimestamp(),
                createdAt:           admin.firestore.FieldValue.serverTimestamp(),
                approvalRequiredBy:  adminUids,
                logs: [{
                    action:    'Staged',
                    uid,
                    userName:  userData.displayName || userData.email || 'Unknown',
                    email:     userData.email || 'unknown',
                    details:   `Provision queued for admin approval (${resourceData.type})`,
                    storage:   'Staging',
                    timestamp: new Date().toISOString()
                }]
            };

            const docRef = await db.collection('pending_provisions').add(provisionData);
            return docRef.id;

        } catch (error) {
            console.error('[STAGING] Error creating staging provision:', error);
            throw error;
        }
    }

    /**
     * Retrieve a single pending provision by ID, verifying org ownership.
     */
    async getProvisionById(provisionId, orgId) {
        const db = getDb();
        const doc = await db.collection('pending_provisions').doc(provisionId).get();
        if (!doc.exists) throw new Error('Pending provision not found');

        const data = doc.data();
        if (data.orgId !== orgId) throw new Error('Provision does not belong to this organization');

        return {
            id: doc.id,
            ...data,
            stagedAt:  data.stagedAt?.toDate  ? data.stagedAt.toDate().toISOString()  : data.stagedAt,
            createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : data.createdAt
        };
    }

    /**
     * Get all pending provisions for an organization (Admin/Owner check done in the route).
     */
    async getPendingProvisions(orgId) {
        const db = getDb();
        try {
            const snapshot = await db.collection('pending_provisions')
                .where('orgId', '==', orgId)
                .get();

            const provisions = snapshot.docs.map(doc => {
                const data = doc.data();
                return {
                    id: doc.id,
                    ...data,
                    stagedAt:  data.stagedAt?.toDate  ? data.stagedAt.toDate().toISOString()  : data.stagedAt,
                    createdAt: data.createdAt?.toDate ? data.createdAt.toDate().toISOString() : data.createdAt
                };
            });

            // Sort newest first
            provisions.sort((a, b) => new Date(b.stagedAt || 0) - new Date(a.stagedAt || 0));
            return provisions;

        } catch (error) {
            console.error('[STAGING] Error getting pending provisions:', error);
            throw error;
        }
    }

    /**
     * Approve a pending provision: move it to the live resources collection.
     */
    async approveProvision(provisionId, approverUid, orgId, additionalNotes = '') {
        const db = getDb();
        try {
            const provisionDoc = await db.collection('pending_provisions').doc(provisionId).get();
            if (!provisionDoc.exists) throw new Error('Pending provision not found');

            const provisionData = provisionDoc.data();
            if (provisionData.orgId !== orgId) throw new Error('Provision orgId does not match');

            // Get approver display info
            const approverDoc = await db.collection('users').doc(approverUid).get();
            const approverName = approverDoc.exists
                ? (approverDoc.data().displayName || approverDoc.data().email || 'Unknown')
                : 'Unknown';

            // Build the live resource document
            const resourceData = {
                ...provisionData,
                logs: [{
                    action:    'Created',
                    uid:       provisionData.creatorUid,
                    userName:  provisionData.creatorName  || 'Unknown',
                    email:     provisionData.creatorEmail || 'unknown',
                    details:   `Provision approved by ${approverName}${additionalNotes ? ` — ${additionalNotes}` : ''}`,
                    storage:   'Firestore',
                    timestamp: new Date().toISOString()
                }],
                approvedBy:     approverUid,
                approvedByName: approverName,
                approvedAt:     admin.firestore.FieldValue.serverTimestamp(),
                status:         PROVISION_STATUS.ACTIVE
            };

            // Remove staging-only fields before publishing
            delete resourceData.stagedAt;
            delete resourceData.approvalRequiredBy;

            const resourceRef = await db.collection('resources').add(resourceData);
            await provisionDoc.ref.delete();

            await this.logActivity(approverUid, 'PROVISION_APPROVED', {
                provisionId,
                resourceId:   resourceRef.id,
                resourceName: provisionData.name,
                orgId,
                approverName,
                notes:        additionalNotes
            }, orgId);

            return {
                success:    true,
                resourceId: resourceRef.id,
                provisionId,
                message:    'Provision approved and published as live resource'
            };

        } catch (error) {
            console.error('[STAGING] Error approving provision:', error);
            throw error;
        }
    }

    /**
     * Deny a pending provision: remove it from staging and log the decision.
     */
    async denyProvision(provisionId, denierUid, orgId, reason = '') {
        const db = getDb();
        try {
            const provisionDoc = await db.collection('pending_provisions').doc(provisionId).get();
            if (!provisionDoc.exists) throw new Error('Pending provision not found');

            const provisionData = provisionDoc.data();
            if (provisionData.orgId !== orgId) throw new Error('Provision orgId does not match');

            const denierDoc = await db.collection('users').doc(denierUid).get();
            const denierName = denierDoc.exists
                ? (denierDoc.data().displayName || denierDoc.data().email || 'Unknown')
                : 'Unknown';

            await provisionDoc.ref.delete();

            await this.logActivity(denierUid, 'PROVISION_DENIED', {
                provisionId,
                resourceName: provisionData.name,
                orgId,
                denierName,
                reason: reason || 'No reason provided'
            }, orgId);

            return {
                success:     true,
                provisionId,
                message:     'Provision denied and removed from staging'
            };

        } catch (error) {
            console.error('[STAGING] Error denying provision:', error);
            throw error;
        }
    }

    /**
     * Update the status of an existing pending provision (e.g., for "recalled" state).
     */
    async updateProvisionStatus(provisionId, newStatus, updaterUid) {
        const db = getDb();
        try {
            const provisionRef  = db.collection('pending_provisions').doc(provisionId);
            const provisionDoc  = await provisionRef.get();
            if (!provisionDoc.exists) throw new Error('Pending provision not found');

            await provisionRef.update({
                status:    newStatus,
                updatedBy: updaterUid,
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            return { success: true, status: newStatus };
        } catch (error) {
            console.error('[STAGING] Error updating provision status:', error);
            throw error;
        }
    }

    // ===== HELPER METHODS =====

    /**
     * Return an array of UIDs for all Admin and Owner members in an org.
     */
    async getAdminOrOwnerUids(orgId) {
        const db = getDb();
        try {
            const snapshot = await db.collection('org_members')
                .where('orgId', '==', orgId)
                .where('role', 'in', [ROLES.OWNER, ROLES.ADMIN])
                .get();

            return snapshot.docs.map(doc => doc.data().uid);
        } catch (error) {
            console.error('[STAGING] Error getting admin/owner UIDs:', error);
            return [];
        }
    }

    /**
     * Get summary statistics for the staging queue of an org.
     */
    async getStagingStats(orgId) {
        const db = getDb();
        try {
            const snapshot = await db.collection('pending_provisions')
                .where('orgId', '==', orgId)
                .get();

            let totalPending = 0;
            const typeCounts = {};

            snapshot.forEach(doc => {
                const data = doc.data();
                totalPending++;
                typeCounts[data.type] = (typeCounts[data.type] || 0) + 1;
            });

            return { totalPending, typeCounts };

        } catch (error) {
            console.error('[STAGING] Error getting staging stats:', error);
            throw error;
        }
    }

    /**
     * Clean up old denied provisions from the collection.
     * (Provisions are actually deleted on denial, so this cleans any orphans.)
     */
    async cleanupOldDeniedProvisions(daysToKeep = 30) {
        const db = getDb();
        try {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

            const snapshot = await db.collection('pending_provisions')
                .where('status', '==', STAGING_STATUS.DENIED)
                .get();

            if (snapshot.empty) return { cleaned: 0 };

            const batch    = db.batch();
            let   cleaned  = 0;

            snapshot.forEach(doc => {
                const data = doc.data();
                const stagedDate = data.stagedAt?.toDate ? data.stagedAt.toDate() : null;
                if (stagedDate && stagedDate < cutoffDate) {
                    batch.delete(doc.ref);
                    cleaned++;
                }
            });

            if (cleaned > 0) {
                await batch.commit();
                console.log(`[STAGING] Cleaned up ${cleaned} old denied provisions`);
            }

            return { cleaned };

        } catch (error) {
            console.error('[STAGING] Error cleaning up old provisions:', error);
            throw error;
        }
    }

    /**
     * Log an activity entry (for staging-originated actions).
     */
    async logActivity(uid, action, details, orgId = null) {
        const db = getDb();
        try {
            const userDoc  = await db.collection('users').doc(uid).get();
            const userData = userDoc.exists ? userDoc.data() : null;

            await db.collection('activity_logs').add({
                uid,
                email:     userData?.email       || 'anonymous',
                userName:  userData?.displayName || userData?.email || 'anonymous',
                action,
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                details,
                ip:        'server-internal',
                orgId
            });
        } catch (error) {
            console.error('[STAGING] Error logging activity:', error);
            // Never throw from logging — it should never break the main operation
        }
    }

    // ===== VALIDATION =====

    validateProvisionData(data) {
        const errors = [];
        if (!data.name || data.name.trim().length < 2) errors.push('Resource name must be at least 2 characters');
        if (!data.type)                                  errors.push('Resource type is required');
        if (!data.orgId)                                 errors.push('orgId is required');
        return { isValid: errors.length === 0, errors };
    }

    // ===== ACCESSORS FOR CONSTANTS =====
    getROLES()           { return ROLES;           }
    getSTAGING_STATUS()  { return STAGING_STATUS;  }
    getPROVISION_STATUS(){ return PROVISION_STATUS; }
}

const stagingWorkflow = new StagingWorkflow();

module.exports = {
    StagingWorkflow,
    stagingWorkflow,
    STAGING_STATUS,
    PROVISION_STATUS
};