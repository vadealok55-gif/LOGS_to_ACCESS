import React, { useState, useEffect } from 'react';
import emailjs from '@emailjs/browser';
import {
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    signInWithPopup,
    signOut,
    onAuthStateChanged
} from 'firebase/auth';
import { auth, googleProvider } from './firebase';
import {
    Building, Copy, User, MapPin, UserCheck, RefreshCw, MailCheck,
    Settings, ArrowLeft, Paperclip, Activity, History, FileText,
    Shield, Lock, Unlock, Mail, KeyRound, LogIn, UserPlus, LogOut, Edit2,
    Globe, Folder, File, Database, Server, Search, Plus, X, Terminal, Check,
    Users, Sun, Moon, Zap, AlertCircle
} from 'lucide-react';
import './index.css';

// --- CONSTANTS & DATA STRUCTURES ---
const PRIVILEGES = ['READ', 'WRITE', 'EXECUTE', 'BILLING', 'NETWORK', 'INFRASTRUCTURE'];
const DEFAULT_ROLES = ['Owner', 'Manager', 'Developer', 'Viewer'];
const ICONS = { Folder, File, Database, Globe, Server };
const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';

const DEFAULT_MATRIX = {
    Owner: Object.fromEntries(PRIVILEGES.map(p => [p, true])),
    Manager: { READ: true, WRITE: true, EXECUTE: true, BILLING: false, NETWORK: false, INFRASTRUCTURE: false },
    Developer: { READ: true, WRITE: true, EXECUTE: true, BILLING: false, NETWORK: false, INFRASTRUCTURE: false },
    Viewer: { READ: true, WRITE: false, EXECUTE: false, BILLING: false, NETWORK: false, INFRASTRUCTURE: false },
};

const FALLBACK_RESOURCES = [
    { id: 1, name: 'Production DB Clusters', type: 'Database', tags: ['INFRASTRUCTURE', 'READ'], status: 'healthy', traffic: '450 rq/s' },
    { id: 2, name: 'Billing Reports Q1', type: 'Folder', tags: ['BILLING', 'READ'], status: 'archived', traffic: '-' },
    { id: 3, name: 'API Gateway Config', type: 'File', tags: ['NETWORK', 'WRITE'], status: 'active', traffic: '1.2k rq/s' },
    { id: 4, name: 'Public Asset CDN', type: 'Globe', tags: ['READ'], status: 'active', traffic: '8.5k rq/s' },
    { id: 5, name: 'Core Processing Daemon', type: 'Server', tags: ['EXECUTE', 'INFRASTRUCTURE'], status: 'degraded', traffic: '90 rq/s' },
];

// --- API UTILS ---
const fetchWithAuth = async (endpoint, user, options = {}) => {
    if (!user) return null;
    const token = await user.getIdToken();
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...options.headers
    };

    // Add impersonation header if present in local storage
    const impUid = localStorage.getItem('nexusguard_impersonate_uid');
    if (impUid) {
        headers['x-impersonate-uid'] = impUid;
    }

    const res = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'API Error');
    }
    return res.json();
};

// --- UI COMPONENTS ---
const Toast = ({ message, type = 'info', onClose }) => (
    <div className={`fixed bottom-4 right-4 flex items-center gap-3 px-4 py-3 rounded-md shadow-lg border z-50
    ${type === 'success' ? 'bg-green-900/50 border-green-500/50 text-green-100' :
            type === 'error' ? 'bg-red-900/50 border-red-500/50 text-red-100' :
                'bg-brand/20 border-brand/50 text-blue-100'}`}>
        {type === 'success' ? <Check size={18} /> : type === 'error' ? <X size={18} /> : <Shield size={18} />}
        <p className="text-sm font-medium">{message}</p>
        <button onClick={onClose} className="ml-2 hover:opacity-75"><X size={16} /></button>
    </div>
);

// --- MAIN APPLICATION ---
export default function App() {
    // Firebase Auth State
    const [firebaseUser, setFirebaseUser] = useState(null);
    const [authLoading, setAuthLoading] = useState(true);
    const [authMode, setAuthMode] = useState('login'); // 'login' | 'signup'
    const [authError, setAuthError] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [showPassword, setShowPassword] = useState(false);

    // App State
    const [currentUser, setCurrentUser] = useState(null);
    const [currentOrg, setCurrentOrg] = useState(null);
    const [view, setView] = useState('auth'); // auth, orgSelect, dashboard
    const [activeTab, setActiveTab] = useState('resources');

    // Data
    const [acm] = useState(DEFAULT_MATRIX);
    const [resources, setResources] = useState(FALLBACK_RESOURCES);
    const [pendingRequests, setPendingRequests] = useState([]);
    const [myJoinRequests, setMyJoinRequests] = useState([]);
    const [isCreating, setIsCreating] = useState(false);
    const [provisionType, setProvisionType] = useState('Server');
    const [provisionName, setProvisionName] = useState('');
    const [impersonatedUid, setImpersonatedUid] = useState(localStorage.getItem('nexusguard_impersonate_uid'));
    const [editingResource, setEditingResource] = useState(null);
    const [selectedResource, setSelectedResource] = useState(null); // provision detail view
    const [provisionDetail, setProvisionDetail] = useState([]); // {resource, members[]}
    const [provisionDetailLoading, setProvisionDetailLoading] = useState(false);
    const [selectedGroupDetail, setSelectedGroupDetail] = useState(null);
    const [detailTab, setDetailTab] = useState('members'); // 'members' | 'manage'
    const [assigningGroup, setAssigningGroup] = useState(null);
    const [userOrgs, setUserOrgs] = useState([]);
    const [orgMembers, setOrgMembers] = useState([]);
    const [orgGroups, setOrgGroups] = useState([]);
    const [showImpersonateModal, setShowImpersonateModal] = useState(false);
    const [impersonateTargetUid, setImpersonateTargetUid] = useState('');
    const [profile, setProfile] = useState(null);
    const [verificationCode, setVerificationCode] = useState('');
    const [isVerifying, setIsVerifying] = useState(false);
    const [resendCooldown, setResendCooldown] = useState(0); // seconds remaining before resend allowed
    const [userActivity, setUserActivity] = useState([]);

    // Theme Management
    const [theme, setTheme] = useState(localStorage.getItem('nexusguard_theme') || 'dark');

    // Terminal
    const [termInput, setTermInput] = useState('');
    const [termOutput, setTermOutput] = useState([
        { type: 'system', text: 'Sovereign Terminal v1.0.0 initialized.' },
        { type: 'system', text: 'Type "help" for a list of commands.' }
    ]);

    // UI
    const [toast, setToast] = useState(null);
    const showToast = (msg, type) => {
        setToast({ message: msg, type });
        setTimeout(() => setToast(null), 4000);
    };

    // Apply Theme
    useEffect(() => {
        document.documentElement.setAttribute('data-theme', theme);
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
        localStorage.setItem('nexusguard_theme', theme);
    }, [theme]);

    const toggleTheme = () => setTheme(prev => prev === 'dark' ? 'light' : 'dark');
    
    // Initialize EmailJS
    useEffect(() => {
        const publicKey = import.meta.env.VITE_EMAILJS_PUBLIC_KEY;
        if (publicKey && publicKey !== 'your_public_key_here') {
            emailjs.init(publicKey);
        }
    }, []);

    // --- Firebase Auth State Listener ---
    useEffect(() => {

        const unsubscribe = onAuthStateChanged(auth, async (user) => {
            setFirebaseUser(user);
            if (user) {
                // Instantly move away from auth screen to improve perceived speed
                setView('orgSelect');
                
                try {
                    const data = await fetchWithAuth('/health', user);
                    setCurrentUser({
                        ...data.user,
                        name: data.user.displayName || data.user.email
                    });
                    fetchUserOrgs(user);
                    fetchMyJoinRequests();
                    showToast(`Profile synced: ${user.email}`, 'success');
                } catch (err) {
                    console.error('Identity validation error:', err);
                    showToast(`Identity check failed: ${err.message}`, 'error');
                    showToast('Profile sync delayed - retrying...', 'info');
                    // We stay in orgSelect view, and user can try switching orgs to trigger new fetches
                }
            } else {
                setView('auth');
                setCurrentUser(null);
                setCurrentOrg(null);
            }
            setAuthLoading(false);
        });
        return () => unsubscribe();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    useEffect(() => {
        if (firebaseUser && activeTab === 'profile') {
            fetchProfile();
            fetchUserActivity();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [firebaseUser, activeTab]);


    const fetchUserOrgs = async (user) => {
        try {
            const data = await fetchWithAuth('/user/organizations', user);
            setUserOrgs(data.organizations || []);
        } catch (err) {
            console.error('Fetch orgs error:', err);
        }
    };

    // --- HELPER UTILS ---
    const getAuthErrorMessage = (error) => {
        const code = error.code || error.message;
        switch (code) {
            case 'auth/user-not-found':
            case 'auth/wrong-password':
            case 'auth/invalid-credential':
                return 'Invalid email or password. Please check your credentials.';
            case 'auth/email-already-in-use':
                return 'This email is already registered. Try signing in.';
            case 'auth/weak-password':
                return 'Password is too weak. Please use at least 6 characters.';
            case 'auth/invalid-email':
                return 'Please enter a valid email address.';
            case 'auth/network-request-failed':
                return 'Connection error. Please check your internet.';
            case 'auth/too-many-requests':
                return 'Too many failed attempts. Please try again later.';
            default:
                return code.replace('auth/', '').replace(/-/g, ' ');
        }
    };

    // --- FETCH RESOURCES ---
    const fetchResources = async (orgId) => {
        if (!firebaseUser) return;
        try {
            const data = await fetchWithAuth(`/resources?orgId=${orgId}`, firebaseUser);
            if (data.resources) {
                setResources(data.resources);
            }
            showToast(`Resources loaded (${data.source})`, 'success');
        } catch {
            showToast('Backend offline - using local resources', 'info');
        }
    };

    // --- FETCH MEMBERS & GROUPS ---
    const fetchOrgMembers = async (orgId) => {
        if (!firebaseUser) return;
        try {
            const data = await fetchWithAuth(`/org-members?orgId=${orgId}`, firebaseUser);
            if (data.members) setOrgMembers(data.members);
        } catch (err) {
            console.error('Failed to fetch members:', err);
        }
    };

    const fetchOrgGroups = async (orgId) => {
        if (!firebaseUser) return;
        try {
            const data = await fetchWithAuth(`/groups?orgId=${orgId}`, firebaseUser);
            if (data.groups) setOrgGroups(data.groups);
        } catch (err) {
            console.error('Failed to fetch groups:', err);
        }
    };

    const fetchProfile = async () => {
        if (!firebaseUser) return;
        try {
            const data = await fetchWithAuth('/profile', firebaseUser);
            if (data && data.profile) setProfile(data.profile);
        } catch (err) {
            console.error('Profile fetch error:', err);
            showToast(`Failed to load profile: ${err.message}`, 'error');
        }
    };

    const fetchUserActivity = async () => {
        if (!firebaseUser) return;
        try {
            const data = await fetchWithAuth('/user/activity', firebaseUser);
            if (data && data.logs) setUserActivity(data.logs);
        } catch (err) {
            console.error('Activity fetch error:', err);
        }
    };

    const openProvisionDetail = async (res) => {
        setSelectedResource(res);
        setProvisionDetail(null);
        setProvisionDetailLoading(true);
        setDetailTab('members');
        try {
            const data = await fetchWithAuth(`/resources/${res.id}/detail?orgId=${currentOrg.id}`, firebaseUser);
            setProvisionDetail(data);
        } catch (err) {
            showToast(`Could not load provision details: ${err.message}`, 'error');
            setProvisionDetail({ resource: res, members: [] });
        } finally {
            setProvisionDetailLoading(false);
        }
    };

    // --- AUTH HANDLERS ---
    const handleSignup = async (email, password) => {
        if (!email.includes('@')) return setAuthError('Valid email required');
        if (password.length < 6) return setAuthError('Password must be 6+ characters');
        
        setAuthError('');
        setIsSubmitting(true);
        try {
            await createUserWithEmailAndPassword(auth, email, password);
            showToast('Account created successfully!', 'success');
        } catch (err) {
            setAuthError(getAuthErrorMessage(err));
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleLogin = async (email, password) => {
        setAuthError('');
        setIsSubmitting(true);
        try {
            const userCredential = await signInWithEmailAndPassword(auth, email, password);
            showToast('Welcome back!', 'success');
            try {
                // Log the login silently
                await fetchWithAuth('/user/log-login', userCredential.user, { method: 'POST' });
            } catch (err) {
                console.error('Failed to log login:', err);
            }
        } catch (err) {
            setAuthError(getAuthErrorMessage(err));
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleGoogleSignIn = async () => {
        setAuthError('');
        setIsSubmitting(true);
        try {
            const userCredential = await signInWithPopup(auth, googleProvider);
            showToast('Google sign-in successful!', 'success');
            try {
                // Log the login silently
                await fetchWithAuth('/user/log-login', userCredential.user, { method: 'POST' });
            } catch (err) {
                console.error('Failed to log Google login:', err);
            }
        } catch (err) {
            if (err.code !== 'auth/popup-closed-by-user') {
                setAuthError(getAuthErrorMessage(err));
            }
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleLogout = async () => {
        await signOut(auth);
        setCurrentUser(null);
        setCurrentOrg(null);
        setView('auth');
        showToast('Disconnected', 'info');
    };
    // --- ORG HANDLERS ---
    const handleCreateOrg = async (orgName) => {
        try {
            const data = await fetchWithAuth('/organizations', firebaseUser, {
                method: 'POST',
                body: JSON.stringify({ name: orgName, ownerUid: firebaseUser.uid })
            });

            const newOrg = { id: data.id, name: data.name, role: 'Admin' };
            setUserOrgs([...userOrgs, newOrg]);
            handleSelectOrg(newOrg);
            showToast(`Organization "${orgName}" created`, 'success');
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleSelectOrg = (org) => {
        const baseUser = currentUser || {
            uid: firebaseUser?.uid,
            email: firebaseUser?.email,
            name: firebaseUser?.displayName || firebaseUser?.email || 'User'
        };
        setCurrentUser({ ...baseUser, role: org.role, orgId: org.id });
        setCurrentOrg(org);
        setView('dashboard');
        fetchResources(org.id);
        fetchPendingRequests(org.id);
        fetchOrgMembers(org.id);
        fetchOrgGroups(org.id);
    };

    const handleSwitchOrg = () => {
        setCurrentOrg(null);
        setView('orgSelect');
        fetchUserOrgs(firebaseUser);
    };

    const handleJoinOrg = async (orgId, requestedRole, workDetails) => {
        if (!orgId || !orgId.trim() || !workDetails.trim()) {
            showToast('Please enter an Organization ID and Work Details', 'error');
            return;
        }
        try {
            const data = await fetchWithAuth('/join-requests', firebaseUser, {
                method: 'POST',
                body: JSON.stringify({ 
                    orgId: orgId.trim(),
                    requestedRole,
                    workDetails: workDetails.trim()
                })
            });
            showToast(`Request sent to join "${data.orgName}". Awaiting admin approval.`, 'success');
            fetchMyJoinRequests();
        } catch (err) {
            showToast(err.message || 'Failed to send join request', 'error');
        }
    };

    const fetchMyJoinRequests = async () => {
        if (!firebaseUser) return;
        try {
            const data = await fetchWithAuth('/join-requests/mine', firebaseUser);
            setMyJoinRequests(data.requests || []);
        } catch (err) {
            console.error('Fetch my requests error:', err);
        }
    };

    const fetchPendingRequests = async (orgId) => {
        if (!firebaseUser || !orgId) return;
        try {
            const data = await fetchWithAuth(`/join-requests?orgId=${orgId}`, firebaseUser);
            setPendingRequests(data.requests || []);
        } catch {
            // Non-admin gets 403, just ignore
            setPendingRequests([]);
        }
    };

    const handleApproveRequest = async (requestId, assignedRole) => {
        try {
            await fetchWithAuth(`/join-requests/${requestId}/approve`, firebaseUser, { 
                method: 'PUT',
                body: JSON.stringify({ assignedRole })
            });
            showToast('Request approved!', 'success');
            fetchPendingRequests(currentOrg?.id);
            fetchOrgMembers(currentOrg?.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleDenyRequest = async (requestId) => {
        try {
            await fetchWithAuth(`/join-requests/${requestId}/deny`, firebaseUser, { method: 'PUT' });
            showToast('Request denied.', 'info');
            fetchPendingRequests(currentOrg?.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleCreateResource = async (resourceData) => {
        try {
            await fetchWithAuth('/resources', firebaseUser, {
                method: 'POST',
                body: JSON.stringify({ ...resourceData, orgId: currentOrg.id })
            });
            showToast('Resource provisioned', 'success');
            fetchResources(currentOrg.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleDeleteResource = async (id) => {
        try {
            await fetchWithAuth(`/resources/${id}`, firebaseUser, { method: 'DELETE' });
            showToast('Resource decommissioned', 'success');
            fetchResources(currentOrg.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleUpdateResource = async (id, updates) => {
        try {
            await fetchWithAuth(`/resources/${id}`, firebaseUser, {
                method: 'PUT',
                body: JSON.stringify({ ...updates, orgId: currentOrg.id })
            });
            showToast('Resource updated', 'success');
            fetchResources(currentOrg.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleUpdateMember = async (memberId, role, groupId) => {
        try {
            await fetchWithAuth(`/org-members/${memberId}`, firebaseUser, {
                method: 'PUT',
                body: JSON.stringify({ role, groupId })
            });
            showToast('Member profile updated', 'success');
            fetchOrgMembers(currentOrg.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const handleCreateGroup = async (groupData) => {
        try {
            await fetchWithAuth('/groups', firebaseUser, {
                method: 'POST',
                body: JSON.stringify({ ...groupData, orgId: currentOrg.id })
            });
            showToast('Custom group initialized', 'success');
            fetchOrgGroups(currentOrg.id);
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    // const handleUpdateGroup = async (groupId, privileges) => {
    //     try {
    //         await fetchWithAuth(`/groups/${groupId}`, firebaseUser, {
    //             method: 'PUT',
    //             body: JSON.stringify({ privileges })
    //         });
    //         showToast('Group privileges updated', 'success');
    //         fetchOrgGroups(currentOrg.id);
    //     } catch (err) {
    //         showToast(err.message, 'error');
    //     }
    // };

    const handleImpersonate = (uid) => {
        localStorage.setItem('nexusguard_impersonate_uid', uid);
        setImpersonatedUid(uid);
        showToast('Swapping identity context...', 'info');
        // Reload to force re-fetch of all context under the new identity
        window.location.reload();
    };

    const stopImpersonating = () => {
        localStorage.removeItem('nexusguard_impersonate_uid');
        setImpersonatedUid(null);
        showToast('Returning to admin context...', 'info');
        window.location.reload();
    };

    const handleUpdateProfile = async (firstName, lastName, location) => {
        setIsSubmitting(true);
        try {
            await fetchWithAuth('/profile', firebaseUser, {
                method: 'PUT',
                body: JSON.stringify({ firstName, lastName, location })
            });
            showToast('Profile updated successfully', 'success');
            fetchProfile();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleSendVerificationEmail = async () => {
        setIsSubmitting(true);
        try {
            // Step 1: Backend generates code and stores it in Firestore
            const data = await fetchWithAuth('/profile/verify-email/send', firebaseUser, { method: 'POST' });
            
            // Step 2: Frontend sends the email via EmailJS browser SDK
            const serviceId = import.meta.env.VITE_EMAILJS_SERVICE_ID;
            const templateId = import.meta.env.VITE_EMAILJS_TEMPLATE_ID;
            const publicKey = import.meta.env.VITE_EMAILJS_PUBLIC_KEY;

            if (serviceId && templateId && publicKey && 
                serviceId !== 'your_service_id_here') {
                const targetEmail = data.email || profile?.email || firebaseUser?.email;
                await emailjs.send(serviceId, templateId, {
                    verification_code: data.code,
                    passcode: data.code, // Matching the user's template variable
                    Verification: '10 minutes', // Matching the user's template variable
                    to_email: targetEmail,
                    user_email: targetEmail,
                    email: targetEmail,
                    reply_to: targetEmail,
                    system_name: 'NexussGuard' // Matching spelling in template
                }, publicKey);
                showToast(`Verification code sent to ${targetEmail}. Check your inbox!`, 'success');
            } else {
                // Fallback: show code in toast (dev mode)
                showToast(data.message || `Code: ${data.code}`, 'success');
            }

            setIsVerifying(true);
            // Start 60-second cooldown
            setResendCooldown(60);
            const timer = setInterval(() => {
                setResendCooldown(prev => {
                    if (prev <= 1) { clearInterval(timer); return 0; }
                    return prev - 1;
                });
            }, 1000);
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleConfirmVerification = async () => {
        if (!verificationCode || verificationCode.length !== 6) return showToast('Please enter the 6-digit code', 'error');
        setIsSubmitting(true);
        try {
            const data = await fetchWithAuth('/profile/verify-email/confirm', firebaseUser, {
                method: 'POST',
                body: JSON.stringify({ code: verificationCode })
            });
            showToast(data.message || 'Email verified! Your identity is confirmed.', 'success');
            setIsVerifying(false);
            setVerificationCode('');
            setResendCooldown(0);
            fetchProfile();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDeleteGroup = async (groupId) => {
        try {
            await fetchWithAuth(`/groups/${groupId}`, firebaseUser, { method: 'DELETE' });
            showToast('Group decommissioned', 'success');
            fetchOrgGroups(currentOrg.id);
            fetchOrgMembers(currentOrg.id); // Refresh members as their group might have been removed
        } catch (err) {
            showToast(err.message, 'error');
        }
    };

    const togglePrivilege = () => {
        showToast('System Policy is currently read-only in this view.', 'info');
    };

    const handleTerminalCommand = (e) => {
        if (e.key !== 'Enter') return;
        const cmd = termInput.trim();
        const newOut = [...termOutput, { type: 'input', text: `> ${cmd}` }];
        switch (cmd.toLowerCase()) {
            case 'help':
                newOut.push({ type: 'output', text: 'Commands: help, clear, whoami, policy --sync, node --status, resources --list' });
                break;
            case 'clear':
                setTermOutput([]);
                setTermInput('');
                return;
            case 'whoami':
                newOut.push({ type: 'output', text: `${currentUser?.name} | Role: ${currentUser?.role} | EID: ${currentUser?.eid} | Firebase UID: ${firebaseUser?.uid}` });
                break;
            case 'policy --sync':
                newOut.push({ type: 'system', text: 'Forcing global matrix sync...' });
                setTimeout(() => showToast('Global Access Policy Synced', 'success'), 800);
                newOut.push({ type: 'success', text: 'Sync complete. 4 nodes updated.' });
                break;
            case 'node --status':
                newOut.push({ type: 'output', text: 'US-East: ONLINE (12ms) | EU-West: ONLINE (45ms) | AP-South: DEGRADED (180ms)' });
                break;
            case 'resources --list':
                newOut.push({ type: 'output', text: `Loaded ${resources.length} resources.` });
                resources.forEach(r => newOut.push({ type: 'output', text: `  [${r.status}] ${r.name} (${r.type})` }));
                break;
            default:
                if (cmd) newOut.push({ type: 'error', text: `Command not found: ${cmd}` });
        }
        setTermOutput(newOut);
        setTermInput('');
    };

    const hasPrivilege = (priv) => {
        if (!currentUser) return false;
        
        const memberData = orgMembers.find(m => m.uid === currentUser.uid);
        if (memberData && memberData.groupId) {
            const group = orgGroups.find(g => g.id === memberData.groupId);
            if (group && group.privileges && group.privileges[priv]) {
                return true; // Custom group privilege takes precedence
            }
        }

        if (!acm[currentUser.role]) return false;
        return acm[currentUser.role][priv] === true;
    };

    const canEditResource = (res) => {
        if (!currentUser) return false;
        if (['Owner', 'Admin'].includes(currentUser.role)) return true;
        
        if (res.type === 'Folder') {
            if (!['Manager'].includes(currentUser.role)) {
                return false;
            }
        }

        if (!hasPrivilege('WRITE')) return false;

        const groupsEmpty = !res.allowedGroups || res.allowedGroups.length === 0;
        const rolesEmpty = !res.allowedRoles || res.allowedRoles.length === 0;
        if (groupsEmpty && rolesEmpty) return true;
        
        const memberData = orgMembers.find(m => m.uid === currentUser.uid);
        if (!memberData) return false;

        const groupAllowed = !groupsEmpty && memberData.groupId && res.allowedGroups.includes(memberData.groupId);
        const roleAllowed = !rolesEmpty && res.allowedRoles.includes(memberData.role);

        return groupAllowed || roleAllowed;
    };

    // --- LOADING STATE ---
    if (authLoading) {
        return (
            <div className="min-h-screen bg-bg-dark flex items-center justify-center">
                <div className="flex flex-col items-center gap-4">
                    <Shield className="text-brand animate-pulse" size={48} />
                    <p className="text-text-secondary">Initializing NexusGuard...</p>
                </div>
            </div>
        );
    }

    // --- AUTH VIEW (Firebase Login/Signup) ---
    if (view === 'auth') {
        return (
            <div className="min-h-screen bg-bg-dark flex items-center justify-center p-4">
                <div className="max-w-md w-full bg-bg-surface border border-border-subtle p-8 rounded-xl shadow-2xl">
                    <div className="flex items-center justify-center gap-3 mb-6">
                        <Shield className="text-brand" size={36} />
                        <h1 className="text-3xl font-bold text-text-primary tracking-tight">NexusGuard</h1>
                    </div>
                    <p className="text-center text-text-secondary mb-8">
                        {authMode === 'login' ? 'Sign in to access your security hub.' : 'Create your NexusGuard identity.'}
                    </p>

                    {authError && (
                        <div className="bg-red-900/30 border border-red-500/50 text-red-200 px-4 py-2 rounded-md mb-4 text-sm">
                            {authError}
                        </div>
                    )}

                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const email = e.target.email.value;
                        const password = e.target.password.value;
                        authMode === 'login' ? handleLogin(email, password) : handleSignup(email, password);
                    }} className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-text-muted mb-1">
                                <Mail size={14} className="inline mr-1" /> Email
                            </label>
                            <input name="email" type="email" required
                                className="w-full bg-bg-dark border border-border-strong rounded-md px-4 py-2.5 text-text-primary focus:outline-none focus:border-brand transition-colors font-sans"
                                placeholder="operator@nexusguard.io" />
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-text-muted mb-1">
                                <KeyRound size={14} className="inline mr-1" /> Password
                            </label>
                            <div className="relative">
                                <input name="password" type={showPassword ? "text" : "password"} required minLength={6}
                                    className="w-full bg-bg-dark border border-border-strong rounded-md px-4 py-2.5 text-text-primary focus:outline-none focus:border-brand transition-colors pr-12 font-sans"
                                    placeholder="••••••••" />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-brand transition-colors"
                                >
                                    {showPassword ? <Unlock size={18} /> : <Lock size={18} />}
                                </button>
                            </div>
                        </div>
                        <button type="submit" disabled={isSubmitting}
                            className={`w-full bg-brand hover:bg-brand-hover text-white font-medium py-2.5 rounded-md transition-all flex justify-center items-center gap-2 ${isSubmitting ? 'opacity-70 cursor-not-allowed scale-95' : ''}`}>
                            {isSubmitting ? (
                                <div className="flex items-center gap-2">
                                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                                    Processing...
                                </div>
                            ) : (
                                authMode === 'login' ? <><LogIn size={18} /> Sign In</> : <><UserPlus size={18} /> Create Account</>
                            )}
                        </button>
                    </form>

                    {/* Divider */}
                    <div className="my-6 flex items-center gap-3">
                        <div className="h-px flex-1 bg-border-strong"></div>
                        <span className="text-xs text-text-muted uppercase tracking-wider">or</span>
                        <div className="h-px flex-1 bg-border-strong"></div>
                    </div>

                    {/* Google Sign-In */}
                    <button onClick={handleGoogleSignIn}
                        className="w-full bg-bg-dark border border-border-strong hover:border-brand text-text-primary font-medium py-2.5 rounded-md transition-colors flex justify-center items-center gap-3">
                        <svg width="18" height="18" viewBox="0 0 24 24">
                            <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4" />
                            <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                            <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                            <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                        </svg>
                        Continue with Google
                    </button>

                    <div className="mt-6 text-center">
                        <button onClick={() => { setAuthMode(authMode === 'login' ? 'signup' : 'login'); setAuthError(''); }}
                            className="text-brand hover:text-brand-hover text-sm transition-colors">
                            {authMode === 'login' ? "Don't have an account? Sign up" : 'Already have an account? Sign in'}
                        </button>
                    </div>
                </div>
                {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
            </div>
        );
    }

    // --- ORG SELECT VIEW ---
    if (view === 'orgSelect') {
        return (
            <div className="min-h-screen bg-bg-dark flex items-center justify-center p-4">
                <div className="max-w-4xl w-full grid md:grid-cols-2 gap-8">
                    {/* Sovereign Creator */}
                    <div className="bg-bg-surface border border-border-subtle p-8 rounded-xl shadow-2xl">
                        <div className="flex items-center gap-3 mb-4">
                            <Shield className="text-brand" size={32} />
                            <h2 className="text-2xl font-bold text-text-primary">Sovereign Creator</h2>
                        </div>
                        <p className="text-text-secondary mb-6 leading-relaxed text-sm">
                            Initialize a new Scratch Org. Build your zero-trust security policy from the ground up.
                        </p>
                        <p className="text-xs text-text-muted mb-4">Signed in as: <span className="text-brand">{firebaseUser?.email}</span></p>
                        <form onSubmit={(e) => { e.preventDefault(); handleCreateOrg(e.target.org.value); }} className="space-y-6">
                            <div className="space-y-2">
                                <label className="text-xs text-text-muted uppercase tracking-widest font-semibold ml-1">Org Identity</label>
                                <input name="org" required
                                    className="w-full bg-bg-dark border border-border-strong rounded-lg px-4 py-3 text-text-primary focus:outline-none focus:border-brand transition-all shadow-inner"
                                    placeholder="e.g. Nexus Security, Global Defense" />
                            </div>
                            <button type="submit" className="w-full bg-brand hover:bg-brand-hover text-white font-bold py-3 rounded-lg transition-all shadow-lg shadow-brand/20 flex justify-center items-center gap-2">
                                <Lock size={18} /> Initialize Org
                            </button>
                        </form>
                    </div>

                    {/* Organization List */}
                    <div className="bg-bg-surface border border-border-subtle p-8 rounded-xl shadow-2xl flex flex-col h-full">
                        <div className="flex items-center gap-3 mb-4">
                            <Users className="text-accent" size={32} />
                            <h2 className="text-2xl font-bold text-text-primary">Your Organizations</h2>
                        </div>
                        <p className="text-text-secondary mb-6 leading-relaxed text-sm">
                            Access and manage security contexts for organizations you are a member of.
                        </p>
                        
                        <div className="flex-1 space-y-3 overflow-y-auto mb-6 pr-2">
                            {userOrgs.length > 0 ? (
                                userOrgs.map(org => (
                                    <button 
                                        key={org.id} 
                                        onClick={() => handleSelectOrg(org)}
                                        className="w-full flex items-center justify-between p-5 bg-bg-dark border border-border-strong rounded-xl hover:border-accent group transition-all"
                                    >
                                        <div className="text-left">
                                            <p className="text-sm font-bold text-text-primary group-hover:text-accent transition-colors">{org.name}</p>
                                            <p className="text-[10px] text-text-muted font-mono uppercase tracking-widest">{org.id}</p>
                                            {org.ownerEmail && <p className="text-[10px] text-text-muted mt-1">Created by: <span className="text-accent">{org.ownerName || org.ownerEmail}</span></p>}
                                        </div>
                                        <div className="flex items-center gap-3">
                                            <span className="text-[10px] bg-accent/10 text-accent px-3 py-1 rounded-full border border-accent/20 font-bold uppercase tracking-tighter">
                                                {org.role}
                                            </span>
                                            <LogIn size={14} className="text-text-muted group-hover:text-accent" />
                                        </div>
                                    </button>
                                ))
                            ) : (
                                <div className="text-center py-8 border border-dashed border-border-strong rounded-lg">
                                    <p className="text-xs text-text-muted">No organizations found.</p>
                                </div>
                            )}

                            {/* My Pending Requests */}
                            {myJoinRequests.filter(r => r.status === 'pending').length > 0 && (
                                <div className="mt-4 pt-4 border-t border-border-subtle">
                                    <p className="text-xs text-text-muted mb-2 uppercase tracking-widest font-medium">Pending Requests</p>
                                    {myJoinRequests.filter(r => r.status === 'pending').map(req => (
                                        <div key={req.id} className="flex items-center justify-between p-3 bg-yellow-900/10 border border-yellow-500/20 rounded-lg mb-2">
                                            <div>
                                                <p className="text-sm text-text-primary font-medium">{req.orgName}</p>
                                                <p className="text-[10px] text-yellow-400">Awaiting approval</p>
                                            </div>
                                            <span className="text-[10px] bg-yellow-500/10 text-yellow-400 px-2 py-0.5 rounded border border-yellow-500/20">Pending</span>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>

                        <form onSubmit={(e) => { 
                            e.preventDefault(); 
                            handleJoinOrg(
                                e.target.eid.value, 
                                e.target.requestedRole.value,
                                e.target.workDetails.value
                            ); 
                            e.target.reset(); 
                        }} className="space-y-5 mt-auto">
                            <div>
                                <label className="text-[10px] text-text-muted mb-2 block uppercase tracking-widest font-bold">Organization ID</label>
                                <input name="eid" required
                                    className="w-full bg-bg-dark border border-border-strong rounded-lg px-4 py-2.5 text-text-primary focus:outline-none focus:border-accent transition-all"
                                    placeholder="Enter unique ID" />
                            </div>
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="text-[10px] text-text-muted mb-2 block uppercase tracking-widest font-bold">Access Role</label>
                                    <select name="requestedRole" required
                                        className="w-full bg-bg-dark border border-border-strong rounded-lg px-4 py-2.5 text-text-primary focus:outline-none focus:border-accent transition-all">
                                        <option value="Viewer">Viewer</option>
                                        <option value="Developer">Developer</option>
                                        <option value="Manager">Manager</option>
                                    </select>
                                </div>
                                <div className="flex flex-col justify-end">
                                    <button type="submit" className="w-full bg-transparent border border-accent text-accent hover:bg-accent/10 font-bold py-2.5 rounded-lg transition-all flex justify-center items-center gap-2">
                                        <LogIn size={18} /> Submit
                                    </button>
                                </div>
                            </div>
                            <div>
                                <label className="text-[10px] text-text-muted mb-2 block uppercase tracking-widest font-bold">Work Details / Reason</label>
                                <textarea name="workDetails" required rows="2"
                                    className="w-full bg-bg-dark border border-border-strong rounded-lg px-4 py-2.5 text-text-primary focus:outline-none focus:border-accent transition-all resize-none"
                                    placeholder="Describe your role..." />
                            </div>
                        </form>
                    </div>

                    {/* Logout */}
                    <div className="md:col-span-2 text-center">
                        <button onClick={handleLogout} className="text-text-muted hover:text-red-400 text-sm transition-colors flex items-center gap-2 mx-auto">
                            <LogOut size={16} /> Sign out ({firebaseUser?.email})
                        </button>
                    </div>
                </div>
                {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
            </div>
        );
    }

    // --- DASHBOARD VIEW ---
    const renderResources = () => (
        <>
            <div className="space-y-4">
            <div className="flex justify-between items-center mb-6">
                <h3 className="text-xl font-bold text-text-primary flex items-center gap-2">
                    <Database className="text-brand" /> Resource Hub
                </h3>
                <div className="flex items-center gap-8">
                    <div className="relative hidden md:block">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" size={16} />
                        <input placeholder="Search resources..." className="pl-9 pr-4 py-1.5 bg-bg-dark border border-border-strong rounded-md text-sm focus:border-brand focus:outline-none" />
                    </div>
                    {(['Owner', 'Admin'].includes(currentUser?.role) || hasPrivilege('WRITE')) && (
                        <button onClick={() => setIsCreating(true)} className="bg-brand hover:bg-brand-hover text-white text-sm font-medium px-4 py-1.5 rounded-md flex items-center gap-2 transition-colors">
                            <Plus size={16} /> Provision
                        </button>
                    )}
                </div>
            </div>

            {isCreating && (
                <div className="bg-bg-surface border border-brand/50 p-6 rounded-lg mb-6 animate-in fade-in slide-in-from-top-4 duration-300">
                    <div className="flex justify-between items-center mb-4">
                        <h4 className="font-bold text-text-primary">New Resource Provisioning</h4>
                        <button onClick={() => setIsCreating(false)} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
                    </div>
                    <form onSubmit={(e) => {
                        e.preventDefault();
                        const formData = new FormData(e.target);
                        handleCreateResource({
                            name: formData.get('name') || provisionName,
                            type: formData.get('type') || provisionType,
                            accessLevel: formData.get('access'),
                            allowedGroups: formData.getAll('allowedGroups'),
                            allowedRoles: formData.getAll('allowedRoles')
                        });
                        setIsCreating(false);
                        setProvisionType('Server');
                        setProvisionName('');
                    }} className="grid md:grid-cols-4 gap-6">
                        <input name="name" value={provisionName} onChange={(e) => setProvisionName(e.target.value)} placeholder="Resource Name" required className="bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm focus:border-brand outline-none" />
                        <select name="type" value={provisionType} onChange={(e) => setProvisionType(e.target.value)} className="bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm focus:border-brand outline-none">
                            <option value="Server">Server</option>
                            <option value="Database">Database</option>
                            <option value="Folder">Folder</option>
                            <option value="File">File</option>
                            <option value="Globe">Globe</option>
                        </select>
                        <select name="access" className="bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm focus:border-brand outline-none">
                            <option value="private">Private</option>
                            <option value="public">Public</option>
                        </select>
                        <button type="submit" className="bg-brand text-white text-sm font-medium py-2 rounded-md hover:bg-brand-hover transition-colors">Confirm</button>
                        
                        {provisionType === 'Folder' && (
                            <div className="md:col-span-4 mt-2">
                                <label className="text-xs text-text-muted mb-2 block flex items-center gap-2"><Folder size={14}/> Select Local Folder to Map</label>
                                <input 
                                    type="file" 
                                    webkitdirectory="true" 
                                    className="bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm text-text-primary file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:bg-brand file:text-white hover:file:bg-brand-hover"
                                    onChange={(e) => {
                                        if (e.target.files && e.target.files.length > 0) {
                                            const firstFile = e.target.files[0];
                                            const folderName = firstFile.webkitRelativePath.split('/')[0];
                                            if (folderName) setProvisionName(folderName);
                                        }
                                    }}
                                />
                            </div>
                        )}

                        {provisionType === 'File' && (
                            <div className="md:col-span-4 mt-2">
                                <label className="text-xs text-text-muted mb-2 block flex items-center gap-2"><File size={14}/> Select Document / Image</label>
                                <input 
                                    type="file" 
                                    accept=".txt, text/plain, .csv, text/csv, .xls, application/vnd.ms-excel, .xlsx, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, image/*"
                                    className="bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm text-text-primary file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:bg-brand file:text-white hover:file:bg-brand-hover"
                                    onChange={(e) => {
                                        if (e.target.files && e.target.files.length > 0) {
                                            const file = e.target.files[0];
                                            setProvisionName(file.name);
                                        }
                                    }}
                                />
                            </div>
                        )}
                        <div className="md:col-span-4 mt-2">
                            <label className="text-xs text-text-muted mb-2 block">Restrict Management to Specific Roles or Groups (Optional)</label>
                            <div className="grid md:grid-cols-2 gap-6">
                                <div className="space-y-2">
                                    <span className="text-xs font-semibold text-text-primary uppercase">Security Groups</span>
                                    <div className="flex flex-wrap gap-2">
                                        {orgGroups.length === 0 ? <span className="text-xs text-text-muted italic">No custom groups initialized.</span> : orgGroups.map(group => (
                                            <label key={group.id} className="flex items-center gap-2 text-sm text-text-primary bg-bg-dark px-3 py-1.5 rounded border border-border-strong cursor-pointer hover:border-brand transition-colors">
                                                <input type="checkbox" name="allowedGroups" value={group.id} className="accent-brand" />
                                                {group.name}
                                            </label>
                                        ))}
                                    </div>
                                </div>
                                <div className="space-y-2">
                                    <span className="text-xs font-semibold text-text-primary uppercase">Base Roles</span>
                                    <div className="flex flex-wrap gap-2">
                                        {['Owner', 'Admin', 'Manager', 'Developer'].map(role => (
                                            <label key={role} className="flex items-center gap-2 text-sm text-text-primary bg-bg-dark px-3 py-1.5 rounded border border-border-strong cursor-pointer hover:border-brand transition-colors">
                                                <input type="checkbox" name="allowedRoles" value={role} className="accent-brand" />
                                                {role}
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    </form>
                </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {resources.length === 0 ? (
                    <div className="col-span-full py-20 text-center border border-dashed border-border-strong rounded-xl">
                        <Database size={48} className="mx-auto mb-4 opacity-20" />
                        <p className="text-text-muted">No resources discovered in this context.</p>
                    </div>
                ) : resources.map(res => {
                    const IconComponent = ICONS[res.type] || Folder;
                    const canSeeLogs = currentUser && (res.creatorUid === currentUser.uid || ['Owner', 'Admin'].includes(currentUser.role));

                    return (
                        <div key={res.id} className="bg-bg-surface border border-border-subtle p-4 rounded-lg hover:border-brand/50 transition-colors group relative overflow-hidden flex flex-col justify-between">
                            <div className="flex items-start gap-4">
                                <button onClick={() => openProvisionDetail(res)} className="p-2 bg-bg-elevated rounded-md text-brand hover:bg-brand/20 transition-colors" title="View provision details">
                                    <IconComponent size={24} />
                                </button>
                                <div className="flex-1 cursor-pointer" onClick={() => openProvisionDetail(res)}>
                                    <h4 className="font-medium text-text-primary hover:text-brand transition-colors">{res.name}</h4>
                                    <div className="flex items-center gap-2 mt-1">
                                        <span className={`w-2 h-2 rounded-full ${res.status === 'healthy' || res.status === 'active' ? 'bg-green-500' : 'bg-text-muted'}`}></span>
                                        <span className="text-xs text-text-secondary capitalize">{res.status}</span>
                                    </div>
                                </div>
                                {canEditResource(res) && (
                                    <div className="flex items-center gap-4 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <button onClick={() => setEditingResource(res)} className="text-text-muted hover:text-brand p-1" title="Manage Resource">
                                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 20h9"></path><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"></path></svg>
                                        </button>
                                        <button onClick={() => handleDeleteResource(res.id)} className="text-text-muted hover:text-red-400 p-1" title="Delete Resource">
                                            <X size={16} />
                                        </button>
                                    </div>
                                )}
                            </div>
                            
                            {/* Resource Logs */}
                            {canSeeLogs && res.logs && res.logs.length > 0 && (
                                <div className="mt-4 pt-3 border-t border-border-strong text-xs">
                                    <p className="font-semibold text-text-muted mb-2 uppercase tracking-tight text-[10px]">Resource Activity Logs</p>
                                    <div className="space-y-1 max-h-24 overflow-y-auto pr-2 custom-scrollbar">
                                        {res.logs.slice().reverse().map((log, idx) => (
                                            <div key={idx} className="flex justify-between items-center bg-bg-dark rounded px-2 py-1">
                                                <div className="flex items-center gap-2 flex-1 truncate">
                                                    <span className={`${log.action === 'Created' ? 'text-green-400' : 'text-yellow-400'} font-medium`}>{log.action}</span>
                                                    <span className="text-text-secondary truncate" title={log.email}>{log.email}</span>
                                                    {log.changes && <span className="text-text-muted text-[10px] hidden sm:inline-block">- Fields: {log.changes}</span>}
                                                </div>
                                                <span className="text-text-muted text-[9px] ml-2 shrink-0">{new Date(log.timestamp).toLocaleDateString()}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                        </div>
                    );
                })}
            </div>
        </div>

            {/* Editing Modal */}
            {editingResource && (
                <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                    <div className="bg-bg-surface border border-border-strong rounded-xl p-6 w-full max-w-md shadow-2xl animate-in fade-in zoom-in-95 duration-200">
                        <div className="flex justify-between items-center mb-6">
                            <h3 className="text-xl font-bold text-text-primary flex items-center gap-2">
                                <Shield className="text-brand" size={20} /> Manage Provision
                            </h3>
                            <button onClick={() => setEditingResource(null)} className="text-text-muted hover:text-text-primary bg-bg-elevated p-1.5 rounded-md"><X size={16} /></button>
                        </div>
                        <form onSubmit={(e) => {
                            e.preventDefault();
                            const formData = new FormData(e.target);
                            handleUpdateResource(editingResource.id, {
                                name: formData.get('name'),
                                accessLevel: formData.get('access'),
                                allowedGroups: formData.getAll('allowedGroups'),
                                allowedRoles: formData.getAll('allowedRoles')
                            });
                            setEditingResource(null);
                        }} className="space-y-4">
                            <div>
                                <label className="text-xs font-medium text-text-muted mb-1 block uppercase tracking-wider">Resource Name</label>
                                <input name="name" defaultValue={editingResource.name} required className="w-full bg-bg-dark border border-border-strong rounded-md px-4 py-2.5 text-sm text-text-primary focus:border-brand outline-none transition-colors" />
                            </div>
                            <div>
                                <label className="text-xs font-medium text-text-muted mb-1 block uppercase tracking-wider">Access Scope</label>
                                <select name="access" defaultValue={editingResource.accessLevel} className="w-full bg-bg-dark border border-border-strong rounded-md px-4 py-2.5 text-sm text-text-primary focus:border-brand outline-none transition-colors">
                                    <option value="private">Private (Organization Internal)</option>
                                    <option value="public">Public (External Access)</option>
                                </select>
                            </div>
                            <div>
                                <label className="text-xs font-medium text-text-muted mb-2 block uppercase tracking-wider">Limit Management To Specific Segments</label>
                                <div className="grid grid-cols-2 gap-3 max-h-48 overflow-y-auto pr-2">
                                    <div className="space-y-2">
                                        <div className="text-xs text-text-muted mb-1">Security Groups</div>
                                        {orgGroups.length === 0 ? <p className="text-sm text-text-muted italic">No custom security groups available.</p> : orgGroups.map(group => {
                                            const isChecked = (editingResource.allowedGroups || []).includes(group.id);
                                            return (
                                                <label key={group.id} className={`flex items-center gap-3 p-2 rounded border cursor-pointer transition-colors ${isChecked ? 'bg-brand/10 border-brand/50' : 'bg-bg-dark border-border-strong hover:border-text-muted'}`}>
                                                    <input type="checkbox" name="allowedGroups" value={group.id} defaultChecked={isChecked} className="accent-brand w-3.5 h-3.5" />
                                                    <span className="text-xs font-medium text-text-primary">{group.name}</span>
                                                </label>
                                            );
                                        })}
                                    </div>
                                    <div className="space-y-2">
                                        <div className="text-xs text-text-muted mb-1">Base Roles</div>
                                        {['Owner', 'Admin', 'Manager', 'Developer'].map(role => {
                                            const isChecked = (editingResource.allowedRoles || []).includes(role);
                                            return (
                                                <label key={role} className={`flex items-center gap-3 p-2 rounded border cursor-pointer transition-colors ${isChecked ? 'bg-brand/10 border-brand/50' : 'bg-bg-dark border-border-strong hover:border-text-muted'}`}>
                                                    <input type="checkbox" name="allowedRoles" value={role} defaultChecked={isChecked} className="accent-brand w-3.5 h-3.5" />
                                                    <span className="text-xs font-medium text-text-primary">{role}</span>
                                                </label>
                                            );
                                        })}
                                    </div>
                                </div>
                                <p className="text-xs text-text-muted mt-2">If no options are selected, any member with WRITE permissions can manage this resource.</p>
                            </div>
                            <div className="flex gap-3 pt-6 mt-2 border-t border-border-strong">
                                <button type="button" onClick={() => setEditingResource(null)} className="flex-1 bg-bg-dark hover:bg-bg-elevated border border-border-strong text-text-primary text-sm font-medium py-2.5 rounded-md transition-colors">Cancel</button>
                                <button type="submit" className="flex-1 bg-brand text-white text-sm font-medium py-2.5 rounded-md hover:bg-brand-hover shadow-lg shadow-brand/20 transition-all">Save Context</button>
                            </div>
                        </form>
                    </div>
                </div>
            )}

            {/* Provision Detail Modal */}
            {selectedResource && (
                <div className="fixed inset-0 bg-black/70 backdrop-blur-md flex items-center justify-center p-4 z-50" onClick={() => setSelectedResource(null)}>
                    <div className="bg-bg-surface border border-border-strong rounded-2xl w-full max-w-5xl max-h-[92vh] overflow-hidden shadow-2xl animate-in fade-in zoom-in-95 duration-200 flex flex-col" onClick={e => e.stopPropagation()}>

                        {/* Modal Header */}
                        <div className="flex items-center gap-4 px-6 py-4 border-b border-border-strong bg-bg-elevated shrink-0">
                            <div className="p-2 bg-brand/10 rounded-lg text-brand">
                                {(() => { const IC = ICONS[selectedResource.type] || Folder; return <IC size={22} />; })()}
                            </div>
                            <div className="flex-1">
                                <h2 className="text-lg font-bold text-text-primary">{selectedResource.name}</h2>
                                <div className="flex items-center gap-3 mt-0.5 flex-wrap">
                                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${selectedResource.accessLevel === 'public' ? 'bg-green-900/50 text-green-300' : 'bg-yellow-900/50 text-yellow-300'}`}>{selectedResource.accessLevel || 'private'}</span>
                                    <span className="text-xs text-text-muted capitalize">{selectedResource.type}</span>
                                    <span className={`w-2 h-2 rounded-full ${selectedResource.status === 'active' || selectedResource.status === 'healthy' ? 'bg-green-500' : 'bg-text-muted'}`}></span>
                                    <span className="text-xs text-text-secondary capitalize">{selectedResource.status}</span>
                                    {selectedResource.allowedRoles?.length > 0 && (
                                        <span className="flex items-center gap-1 text-xs text-text-muted"><Shield size={10} className="text-brand" />{selectedResource.allowedRoles.join(', ')}</span>
                                    )}
                                    {selectedResource.allowedGroups?.length > 0 && (
                                        <span className="flex items-center gap-1 text-xs text-text-muted"><Users size={10} className="text-accent" />{selectedResource.allowedGroups.length} group(s)</span>
                                    )}
                                </div>
                            </div>
                            <button onClick={() => setSelectedResource(null)} className="text-text-muted hover:text-text-primary bg-bg-dark p-2 rounded-lg transition-colors"><X size={16} /></button>
                        </div>

                        <div className="flex border-b border-border-strong bg-bg-dark/40 shrink-0 overflow-x-auto no-scrollbar">
                            {['members', 'logs', 'media', 'manage'].map(tab => (
                                <button
                                    key={tab}
                                    onClick={() => setDetailTab(tab)}
                                    className={`px-6 py-3 text-sm font-medium transition-colors capitalize border-b-2 whitespace-nowrap ${detailTab === tab ? 'text-brand border-brand' : 'text-text-muted border-transparent hover:text-text-primary'}`}
                                >
                                    {tab === 'members' && <div className="flex items-center gap-2"><Users size={14} /> Members</div>}
                                    {tab === 'logs' && <div className="flex items-center gap-2"><Activity size={14} /> Log Activity</div>}
                                    {tab === 'media' && <div className="flex items-center gap-2"><FileText size={14} /> Media</div>}
                                    {tab === 'manage' && <div className="flex items-center gap-2"><Settings size={14} /> Manage</div>}
                                </button>
                            ))}
                        </div>

                        {/* Tab Content */}
                        <div className="flex-1 overflow-y-auto custom-scrollbar">

                            {/* === MEMBERS TAB === */}
                            {detailTab === 'members' && (
                                <>
                                    {provisionDetailLoading ? (
                                        <div className="flex items-center justify-center py-20 text-text-muted">
                                            <svg className="animate-spin mr-3 h-5 w-5 text-brand" fill="none" viewBox="0 0 24 24"><circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/><path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/></svg>
                                            Loading member records...
                                        </div>
                                    ) : provisionDetail && provisionDetail.members.length === 0 ? (
                                        <div className="flex flex-col items-center justify-center py-20 text-text-muted">
                                            <Users size={40} className="mb-3 opacity-30" />
                                            <p className="text-sm font-medium">No users are assigned to this provision yet.</p>
                                            <p className="text-xs mt-1 opacity-60">Assign roles or groups from the <button onClick={() => setDetailTab('manage')} className="underline text-brand">Manage tab</button>.</p>
                                        </div>
                                    ) : (
                                        <table className="w-full text-sm text-left">
                                            <thead className="bg-bg-elevated border-b border-border-strong sticky top-0 z-10">
                                                <tr>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">User</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">Role</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">Group</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">Work / Task</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">Task Status</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">Joined</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {(provisionDetail?.members || []).map((m, idx) => (
                                                    <tr key={m.uid || idx} className="border-b border-border-strong/40 hover:bg-bg-elevated/60 transition-colors">
                                                        <td className="px-5 py-3.5">
                                                            <div className="flex items-center gap-2">
                                                                <div className="w-7 h-7 rounded-full bg-brand/20 text-brand flex items-center justify-center text-xs font-bold shrink-0">{(m.email || '?')[0].toUpperCase()}</div>
                                                                <span className="text-text-primary truncate max-w-[140px]" title={m.email}>{m.email}</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-5 py-3.5">
                                                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${m.role === 'Owner' ? 'bg-purple-900/50 text-purple-300' : m.role === 'Admin' ? 'bg-blue-900/50 text-blue-300' : m.role === 'Manager' ? 'bg-teal-900/50 text-teal-300' : m.role === 'Developer' ? 'bg-orange-900/50 text-orange-300' : 'bg-bg-dark text-text-secondary'}`}>{m.role}</span>
                                                        </td>
                                                        <td className="px-5 py-3.5"><span className="text-text-secondary text-xs">{m.groupName || '-'}</span></td>
                                                        <td className="px-5 py-3.5"><span className="text-text-secondary text-xs max-w-[180px] truncate block" title={m.workDetails || m.taskTitle || ''}>{m.taskTitle || m.workDetails || <span className="text-text-muted italic">-</span>}</span></td>
                                                        <td className="px-5 py-3.5">
                                                            {m.taskStatus ? (
                                                                <span className={`px-2 py-0.5 rounded text-xs font-medium ${m.taskStatus === 'done' ? 'bg-green-900/50 text-green-300' : m.taskStatus === 'in-progress' ? 'bg-yellow-900/50 text-yellow-300' : 'bg-bg-dark text-text-muted'}`}>{m.taskStatus}</span>
                                                            ) : <span className="text-text-muted text-xs">-</span>}
                                                        </td>
                                                        <td className="px-5 py-3.5 text-text-muted text-xs">{m.joinedAt ? new Date(m.joinedAt).toLocaleDateString() : '-'}</td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    )}
                                </>
                            )}

                            {/* === LOG ACTIVITY TAB === */}
                            {detailTab === 'logs' && (
                                <div className="p-0">
                                    {!selectedResource.logs || selectedResource.logs.length === 0 ? (
                                        <div className="flex flex-col items-center justify-center py-20 text-text-muted">
                                            <Activity size={40} className="mb-3 opacity-30" />
                                            <p className="text-sm">No activity logs found for this provision.</p>
                                        </div>
                                    ) : (
                                        <table className="w-full text-sm text-left">
                                            <thead className="bg-bg-elevated border-b border-border-strong sticky top-0 z-10">
                                                <tr>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase w-32">Action</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">User Details</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase">Store / Data</th>
                                                    <th className="px-5 py-3 font-semibold text-text-secondary text-xs uppercase text-right">Timestamp</th>
                                                </tr>
                                            </thead>
                                            <tbody className="divide-y divide-border-strong/40">
                                                {[...selectedResource.logs].reverse().map((log, idx) => (
                                                    <tr key={idx} className="hover:bg-bg-elevated/40 transition-colors">
                                                        <td className="px-5 py-4">
                                                            <div className={`flex items-center gap-2 font-bold text-xs uppercase tracking-wider ${log.action === 'Created' ? 'text-green-400' : 'text-yellow-400'}`}>
                                                                <span className={`w-1.5 h-1.5 rounded-full ${log.action === 'Created' ? 'bg-green-500' : 'bg-yellow-500'}`}></span>
                                                                {log.action}
                                                            </div>
                                                        </td>
                                                        <td className="px-5 py-4">
                                                            <div className="flex flex-col">
                                                                <div className="flex items-center gap-2">
                                                                    <div className="w-6 h-6 rounded-full bg-bg-dark border border-border-strong flex items-center justify-center text-[10px] font-bold text-text-muted">{(log.userName || log.email || '?')[0].toUpperCase()}</div>
                                                                    <span className="text-text-primary font-medium">{log.userName || 'Unknown User'}</span>
                                                                </div>
                                                                <span className="text-[10px] text-text-muted ml-8 leading-tight">{log.email}</span>
                                                                <span className="text-[9px] text-text-muted/60 ml-8 font-mono">UID: {log.uid || 'N/A'}</span>
                                                            </div>
                                                        </td>
                                                        <td className="px-5 py-4">
                                                            <div className="flex flex-col gap-1">
                                                                <div className="flex items-center gap-1.5">
                                                                    <Database size={10} className="text-brand" />
                                                                    <span className="text-xs text-text-secondary font-medium">{log.storage || 'Firestore'}</span>
                                                                </div>
                                                                <div className="text-[11px] text-text-muted leading-relaxed max-w-xs break-words italic">
                                                                    {log.action === 'Created' ? (log.details || `Provision created: ${selectedResource.name}`) : log.changes ? `Updated: ${Object.keys(log.changes).join(', ')}` : 'Manual update'}
                                                                </div>
                                                            </div>
                                                        </td>
                                                        <td className="px-5 py-4 text-right">
                                                            <div className="text-xs text-text-primary mb-0.5">{new Date(log.timestamp).toLocaleDateString()}</div>
                                                            <div className="text-[10px] text-text-muted">{new Date(log.timestamp).toLocaleTimeString()}</div>
                                                        </td>
                                                    </tr>
                                                ))}
                                            </tbody>
                                        </table>
                                    )}
                                </div>
                            )}

                            {/* === MEDIA TAB === */}
                            {detailTab === 'media' && (
                                <div className="p-6">
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                        <div className="space-y-4">
                                            <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider flex items-center gap-2">
                                                <FileText size={16} className="text-brand" /> 
                                                Provision Source & Files
                                            </h3>
                                            <div className="bg-bg-dark/60 border border-border-strong rounded-xl p-5 space-y-4">
                                                <div className="flex items-start gap-4">
                                                    <div className="w-12 h-12 rounded-lg bg-brand/10 border border-brand/20 flex items-center justify-center text-brand shrink-0">
                                                        {(() => { const IC = ICONS[selectedResource.type] || Folder; return <IC size={24} />; })()}
                                                    </div>
                                                    <div className="flex-1 min-w-0">
                                                        <div className="text-sm font-bold text-text-primary truncate">{selectedResource.name}</div>
                                                        <div className="text-xs text-text-muted mt-1">Type: <span className="text-text-secondary">{selectedResource.type}</span></div>
                                                        <div className="text-xs text-text-muted">Format: <span className="text-text-secondary italic">Digital Resource</span></div>
                                                    </div>
                                                </div>
                                                
                                                <div className="pt-4 border-t border-border-strong grid grid-cols-2 gap-4">
                                                    <div>
                                                        <div className="text-[10px] text-text-muted uppercase font-bold tracking-widest mb-1">Created By</div>
                                                        <div className="text-xs text-text-primary flex items-center gap-1.5">
                                                            <User size={12} className="text-accent" />
                                                            <span className="truncate">{selectedResource.creatorEmail || 'System Admin'}</span>
                                                        </div>
                                                    </div>
                                                    <div>
                                                        <div className="text-[10px] text-text-muted uppercase font-bold tracking-widest mb-1">Storage Loc.</div>
                                                        <div className="text-xs text-text-primary flex items-center gap-1.5">
                                                            <Database size={12} className="text-brand" />
                                                            <span>Central Firestore</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            {selectedResource.type === 'File' && (
                                                <div className="bg-brand/5 border border-brand/20 rounded-xl p-5">
                                                    <div className="flex items-center justify-between mb-3">
                                                        <span className="text-xs font-bold text-brand uppercase tracking-widest">Active File</span>
                                                        <span className="text-[10px] bg-brand text-white px-2 py-0.5 rounded-full font-bold">LATEST</span>
                                                    </div>
                                                    <div className="flex items-center gap-3">
                                                        <Paperclip size={16} className="text-brand" />
                                                        <span className="text-sm text-text-primary font-medium truncate">{selectedResource.name}</span>
                                                    </div>
                                                    <button className="w-full mt-4 bg-brand/20 hover:bg-brand/30 text-brand text-xs font-bold py-2 rounded-lg transition-colors border border-brand/30">
                                                        Download / View Document
                                                    </button>
                                                </div>
                                            )}
                                        </div>

                                        <div className="space-y-4">
                                            <h3 className="text-sm font-bold text-text-primary uppercase tracking-wider flex items-center gap-2">
                                                <History size={16} className="text-accent" />
                                                Media Modification History
                                            </h3>
                                            <div className="space-y-3">
                                                {(selectedResource.logs || []).filter(l => l.action === 'Edited' || l.action === 'Created').map((log, i) => (
                                                    <div key={i} className="relative pl-6 pb-4 border-l border-border-strong last:pb-0">
                                                        <div className={`absolute top-0 -left-[5px] w-2.5 h-2.5 rounded-full border-2 border-bg-dark shadow-[0_0_0_1px_rgba(255,255,255,0.05)] ${log.action === 'Created' ? 'bg-green-500' : 'bg-brand'}`}></div>
                                                        <div className="flex flex-col gap-0.5">
                                                            <div className="flex items-center justify-between">
                                                                <span className="text-[11px] font-bold text-text-primary uppercase tracking-tighter">{log.action === 'Created' ? 'Initial Batch' : 'Update Cycle'}</span>
                                                                <span className="text-[10px] text-text-muted">{new Date(log.timestamp).toLocaleDateString()}</span>
                                                            </div>
                                                            <div className="text-xs text-text-secondary mt-0.5">
                                                                {log.action === 'Created' ? (
                                                                    'Media root established in secure vault'
                                                                ) : (
                                                                    <span>Modified by <strong className="text-text-primary">{log.userName || log.email}</strong></span>
                                                                )}
                                                            </div>
                                                            {log.changes && (
                                                                <div className="text-[10px] text-text-muted/60 mt-1 pl-2 border-l border-brand/30 italic">
                                                                    Scope: {Object.keys(log.changes).join(', ')}
                                                                </div>
                                                            )}
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {/* === MANAGE TAB === */}
                            {detailTab === 'manage' && (() => {
                                if (!canEditResource(selectedResource)) {
                                    return (
                                        <div className="flex flex-col items-center justify-center py-20 text-text-muted">
                                            <Lock size={40} className="mb-3 opacity-30" />
                                            <p className="text-sm">You don't have permission to manage this provision.</p>
                                        </div>
                                    );
                                }
                                return (
                                    <form id="manage-provision-form" onSubmit={async (e) => {
                                        e.preventDefault();
                                        const fd = new FormData(e.target);
                                        const newRoles = fd.getAll('manageRoles');
                                        const newGroups = fd.getAll('manageGroups');
                                        const newName = fd.get('manageName') || selectedResource.name;
                                        const newAccess = fd.get('manageAccess') || selectedResource.accessLevel;
                                        try {
                                            await fetchWithAuth(`/resources/${selectedResource.id}`, firebaseUser, {
                                                method: 'PUT',
                                                headers: { 'Content-Type': 'application/json' },
                                                body: JSON.stringify({
                                                    orgId: currentOrg.id,
                                                    name: newName,
                                                    accessLevel: newAccess,
                                                    allowedRoles: newRoles,
                                                    allowedGroups: newGroups
                                                })
                                            });
                                            setSelectedResource(prev => ({ ...prev, name: newName, accessLevel: newAccess, allowedRoles: newRoles, allowedGroups: newGroups }));
                                            setResources(prev => prev.map(x => x.id === selectedResource.id ? { ...x, name: newName, accessLevel: newAccess, allowedRoles: newRoles, allowedGroups: newGroups } : x));
                                            showToast('Provision updated successfully', 'success');
                                            await openProvisionDetail({ ...selectedResource, name: newName, accessLevel: newAccess, allowedRoles: newRoles, allowedGroups: newGroups });
                                            setDetailTab('members');
                                        } catch (err) {
                                            showToast(`Failed to update: ${err.message}`, 'error');
                                        }
                                    }} className="p-6 space-y-6">

                                        {/* Name & Access */}
                                        <div className="grid md:grid-cols-2 gap-4">
                                            <div>
                                                <label className="block text-xs text-text-muted mb-1.5 font-medium uppercase tracking-wide">Provision Name</label>
                                                <input name="manageName" defaultValue={selectedResource.name} className="w-full bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-brand font-sans" />
                                            </div>
                                            <div>
                                                <label className="block text-xs text-text-muted mb-1.5 font-medium uppercase tracking-wide">Access Level</label>
                                                <select name="manageAccess" defaultValue={selectedResource.accessLevel || 'private'} className="w-full bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-brand font-sans">
                                                    <option value="private">Private - Restricted</option>
                                                    <option value="internal">Internal - Org Members</option>
                                                    <option value="public">Public - Anyone</option>
                                                </select>
                                            </div>
                                        </div>

                                        {/* Roles */}
                                        <div>
                                            <label className="block text-xs text-text-muted mb-2 font-medium uppercase tracking-wide flex items-center gap-1.5"><Shield size={12} className="text-brand" />Assign Roles (users with these roles can access)</label>
                                            <div className="flex flex-wrap gap-2">
                                                {['Owner', 'Admin', 'Manager', 'Developer', 'Viewer'].map(role => (
                                                    <label key={role} className="flex items-center gap-2 text-sm text-text-primary bg-bg-dark px-3 py-1.5 rounded-lg border border-border-strong cursor-pointer hover:border-brand transition-colors has-[:checked]:border-brand has-[:checked]:bg-brand/10">
                                                        <input type="checkbox" name="manageRoles" value={role} defaultChecked={selectedResource.allowedRoles?.includes(role)} className="accent-brand" />
                                                        <span className={`text-xs font-medium ${role === 'Owner' ? 'text-purple-300' : role === 'Admin' ? 'text-blue-300' : role === 'Manager' ? 'text-teal-300' : role === 'Developer' ? 'text-orange-300' : 'text-text-secondary'}`}>{role}</span>
                                                    </label>
                                                ))}
                                            </div>
                                            <p className="text-xs text-text-muted mt-1.5 opacity-70">Leave all unchecked to allow any org member with write access.</p>
                                        </div>

                                        {/* Security Groups */}
                                        <div>
                                            <label className="block text-xs text-text-muted mb-2 font-medium uppercase tracking-wide flex items-center gap-1.5"><Users size={12} className="text-accent" />Assign Groups (users in these groups can access)</label>
                                            {orgGroups.length === 0 ? (
                                                <p className="text-xs text-text-muted italic">No custom groups created in this organization yet.</p>
                                            ) : (
                                                <div className="flex flex-wrap gap-2">
                                                    {orgGroups.map(group => (
                                                        <label key={group.id} className="flex items-center gap-2 text-sm text-text-primary bg-bg-dark px-3 py-1.5 rounded-lg border border-border-strong cursor-pointer hover:border-accent transition-colors has-[:checked]:border-accent has-[:checked]:bg-accent/10">
                                                            <input type="checkbox" name="manageGroups" value={group.id} defaultChecked={selectedResource.allowedGroups?.includes(group.id)} className="accent-brand" />
                                                            <span className="text-xs font-medium text-text-primary">{group.name}</span>
                                                        </label>
                                                    ))}
                                                </div>
                                            )}
                                        </div>

                                        {/* File Attachment — only for "File" type provisions */}
                                        {selectedResource.type === 'File' && (
                                            <div>
                                                <label className="block text-xs text-text-muted mb-2 font-medium uppercase tracking-wide flex items-center gap-1.5"><Paperclip size={12} className="text-brand" /> Replace / Attach File</label>
                                                <input
                                                    type="file"
                                                    name="provisionFile"
                                                    accept=".txt, text/plain, .csv, text/csv, .xls, application/vnd.ms-excel, .xlsx, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet, image/*"
                                                    className="w-full bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm text-text-primary file:mr-4 file:py-1 file:px-3 file:rounded-md file:border-0 file:text-xs file:bg-brand file:text-white hover:file:bg-brand-hover"
                                                    onChange={(e) => {
                                                        if (e.target.files && e.target.files[0]) {
                                                            const f = e.target.files[0];
                                                            e.target.closest('form').querySelector('input[name="manageName"]').value = f.name;
                                                        }
                                                    }}
                                                />
                                                <p className="text-xs text-text-muted mt-1.5 opacity-70">Selecting a file will update the provision name to the file name.</p>
                                            </div>
                                        )}

                                        {/* Save Button */}
                                        <div className="flex gap-6 pt-2 border-t border-border-strong">
                                            <button type="button" onClick={() => setDetailTab('members')} className="flex-1 bg-bg-dark hover:bg-bg-elevated border border-border-strong text-text-primary text-sm font-medium py-2.5 rounded-md transition-colors flex items-center justify-center gap-2">
                                                <ArrowLeft size={14} /> Back to Members
                                            </button>
                                            <button type="submit" className="flex-1 bg-brand text-white text-sm font-bold py-2.5 rounded-md hover:bg-brand-hover shadow-lg shadow-brand/20 transition-all">Save Changes</button>
                                        </div>
                                    </form>
                                );
                            })()}
                        </div>

                        {/* Footer with log snippet */}
                        {selectedResource.logs && selectedResource.logs.length > 0 && (() => {
                            const canSee = currentUser && (selectedResource.creatorUid === currentUser.uid || ['Owner','Admin'].includes(currentUser.role));
                            if (!canSee) return null;
                            return (
                                <div className="px-6 py-2.5 border-t border-border-strong bg-bg-dark/60 text-xs text-text-muted shrink-0 flex items-center gap-2">
                                    <span className="font-semibold">Last Activity:</span>
                                    <span className={selectedResource.logs[selectedResource.logs.length - 1].action === 'Created' ? 'text-green-400' : 'text-yellow-400'}>
                                        {selectedResource.logs[selectedResource.logs.length - 1].action}
                                    </span>
                                    <span>by {selectedResource.logs[selectedResource.logs.length - 1].email}</span>
                                    <span className="ml-auto opacity-60">{new Date(selectedResource.logs[selectedResource.logs.length - 1].timestamp).toLocaleString()}</span>
                                </div>
                            );
                        })()}

                    </div>
                </div>
            )}

        </>
    );



    const renderMatrix = () => {
        if (currentUser?.role !== 'Owner') return (
            <div className="flex flex-col items-center justify-center p-12 text-center text-text-muted">
                <Lock size={48} className="mb-4 opacity-50" />
                <h3 className="text-xl font-medium mb-2">Restricted Area</h3>
                <p>Access Control Matrix requires Owner role privileges.</p>
            </div>
        );
        return (
            <div className="space-y-6">
                <div className="flex justify-between items-center">
                    <h3 className="text-xl font-bold text-text-primary flex items-center gap-2">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-brand"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="3" y1="15" x2="21" y2="15"></line><line x1="9" y1="3" x2="9" y2="21"></line><line x1="15" y1="3" x2="15" y2="21"></line></svg>
                        Access Control Matrix
                    </h3>
                    <p className="text-sm text-text-muted">Live Sync: Active</p>
                </div>
                <div className="overflow-x-auto border border-border-strong rounded-lg bg-bg-dark">
                    <table className="w-full text-left text-sm">
                        <thead>
                            <tr className="bg-bg-elevated border-b border-border-strong">
                                <th className="p-4 font-medium text-text-secondary">Role</th>
                                {PRIVILEGES.map(priv => (
                                    <th key={priv} className="p-4 font-medium text-text-secondary text-center tracking-wider text-xs">{priv}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-border-subtle">
                            {Object.keys(acm).map(role => (
                                <tr key={role} className="hover:bg-bg-surface/50 transition-colors">
                                    <td className="p-4 font-medium text-text-primary flex items-center gap-2">
                                        {role === 'Owner' && <Shield size={14} className="text-brand" />}
                                        {role}
                                    </td>
                                    {PRIVILEGES.map(priv => (
                                        <td key={priv} className="p-4 text-center">
                                            <button onClick={() => togglePrivilege(role, priv)} disabled={role === 'Owner'}
                                                className={`w-6 h-6 rounded-sm inline-flex items-center justify-center transition-all
                          ${role === 'Owner' ? 'bg-brand text-white opacity-50 cursor-not-allowed' :
                                                        acm[role][priv] ? 'bg-brand text-white hover:bg-brand-hover shadow-[0_0_10px_rgba(25,127,230,0.4)]' :
                                                            'bg-bg-elevated text-transparent hover:bg-border-strong border border-border-strong'}`}>
                                                {acm[role][priv] && <Check size={14} />}
                                            </button>
                                        </td>
                                    ))}
                                </tr>
                            ))}
                            {orgGroups.length > 0 && (
                                <tr className="bg-bg-dark border-y-2 border-border-strong">
                                    <td colSpan={PRIVILEGES.length + 1} className="p-3 text-xs font-bold text-text-muted uppercase tracking-wider text-center bg-bg-elevated/50">
                                        Custom Groups
                                    </td>
                                </tr>
                            )}
                            {orgGroups.map(group => (
                                <tr key={group.id} className="hover:bg-bg-surface/50 transition-colors">
                                    <td className="p-4 font-medium text-accent flex items-center gap-2">
                                        <Shield size={14} />
                                        {group.name}
                                    </td>
                                    {PRIVILEGES.map(priv => (
                                        <td key={priv} className="p-4 text-center">
                                            <div className={`w-6 h-6 rounded-sm auto mx-auto flex items-center justify-center transition-all ${group.privileges[priv] ? 'bg-accent text-white shadow-[0_0_10px_rgba(20,184,166,0.4)]' : 'bg-bg-elevated text-transparent border border-border-strong'}`}>
                                                {group.privileges[priv] && <Check size={14} />}
                                            </div>
                                        </td>
                                    ))}
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        );
    };

    const renderTerminal = () => {
        if (!hasPrivilege('EXECUTE') && currentUser?.role !== 'Owner') return (
            <div className="flex flex-col items-center justify-center p-12 text-center text-text-muted">
                <Terminal size={48} className="mb-4 opacity-50" />
                <h3 className="text-xl font-medium mb-2">Terminal Locked</h3>
                <p>EXECUTE privilege required for Sovereign Terminal access.</p>
            </div>
        );
        return (
            <div className="h-[600px] flex flex-col bg-[#0d1117] border border-border-strong rounded-lg overflow-hidden font-mono text-sm shadow-inner">
                <div className="flex items-center gap-2 px-4 py-2 bg-bg-surface border-b border-border-strong">
                    <div className="w-3 h-3 rounded-full bg-red-500"></div>
                    <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                    <div className="w-3 h-3 rounded-full bg-green-500"></div>
                    <span className="ml-2 text-text-muted text-xs">root@nexusguard-sovereign:~</span>
                </div>
                <div className="flex-1 overflow-y-auto p-4 space-y-2">
                    {termOutput.map((line, i) => (
                        <div key={i} className={`${line.type === 'input' ? 'text-brand' : line.type === 'error' ? 'text-red-400' : line.type === 'success' ? 'text-green-400' : 'text-text-secondary'}`}>
                            {line.text}
                        </div>
                    ))}
                </div>
                <div className="p-4 border-t border-border-strong bg-[#0d1117] flex items-center gap-2">
                    <span className="text-brand font-bold">~</span>
                    <span className="text-text-muted font-bold">$</span>
                    <input type="text" value={termInput} onChange={(e) => setTermInput(e.target.value)} onKeyDown={handleTerminalCommand}
                        className="flex-1 bg-transparent border-none outline-none text-text-primary" autoFocus spellCheck="false" />
                </div>
        </div>
        );
    };

    const renderOrgDetails = () => {
        if (!currentOrg) return null;
        return (
            <div className="space-y-6 max-w-2xl mx-auto mt-4">
                <div className="flex items-center gap-3 border-b border-border-subtle pb-4 mb-6">
                    <Building className="text-brand" size={28} />
                    <div>
                        <h2 className="text-2xl font-bold text-text-primary">Organization Details</h2>
                        <p className="text-sm text-text-muted">Information and sharing context for {currentOrg.name}</p>
                    </div>
                </div>

                <div className="bg-bg-surface border border-border-strong rounded-xl p-6 space-y-6">
                    <div>
                        <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-2">Organization Name</h3>
                        <p className="text-lg font-medium text-text-primary">{currentOrg.name}</p>
                    </div>

                    <div className="bg-bg-dark border border-border-strong rounded-lg p-5">
                        <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-2">Enterprise ID (Unique Identifier)</h3>
                        <p className="text-sm text-text-secondary mb-3">Share this ID with others so they can request access to this organization.</p>
                        <div className="flex items-center gap-2">
                            <code className="flex-1 bg-black border border-border-subtle rounded px-4 py-3 text-brand font-mono text-sm break-all">
                                {currentOrg.id}
                            </code>
                            <button 
                                onClick={() => {
                                    navigator.clipboard.writeText(currentOrg.id);
                                    showToast('Organization ID copied to clipboard!', 'success');
                                }}
                                className="bg-brand/10 hover:bg-brand/20 text-brand border border-brand/20 p-3 rounded transition-colors flex items-center justify-center"
                                title="Copy ID"
                            >
                                <Copy size={20} />
                            </button>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-4 border-t border-border-subtle">
                        <div>
                            <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1.5"><Shield size={14}/> Your Role</h3>
                            <div className="inline-flex items-center gap-2 bg-accent/10 border border-accent/20 px-3 py-1.5 rounded-md text-accent text-sm font-medium">
                                {currentUser?.role || 'Member'}
                            </div>
                        </div>
                        <div>
                            <h3 className="text-xs font-bold text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1.5"><User size={14}/> Created By</h3>
                            <p className="text-sm font-medium text-text-primary">{currentOrg.ownerName || 'Unknown Admin'}</p>
                            <p className="text-xs text-text-muted">{currentOrg.ownerEmail || 'No email provided'}</p>
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    const renderImpersonateModal = () => {
        if (!showImpersonateModal) return null;

        return (
            <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[100] flex items-center justify-center p-4">
                <div className="bg-bg-surface border border-border-strong w-full max-w-md rounded-2xl shadow-2xl overflow-hidden animate-in fade-in zoom-in duration-200">
                    <div className="p-6 border-b border-border-subtle bg-brand/5 flex justify-between items-center">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-brand/10 rounded-lg">
                                <User className="text-brand" size={20} />
                            </div>
                            <h3 className="text-lg font-bold text-text-primary">Switch Context</h3>
                        </div>
                        <button onClick={() => setShowImpersonateModal(false)} className="text-text-muted hover:text-text-primary transition-colors">
                            <X size={20} />
                        </button>
                    </div>
                    
                    <div className="p-6 space-y-4">
                        <p className="text-sm text-text-secondary leading-relaxed">
                            Enter the <span className="text-brand font-bold uppercase tracking-wider">Unique ID (UID)</span> of the account you wish to impersonate.
                        </p>
                        
                        <div>
                            <label className="block text-[10px] font-bold text-text-muted uppercase tracking-widest mb-1.5 ml-1">Target Account UID</label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-text-muted">
                                    <KeyRound size={16} />
                                </div>
                                <input
                                    type="text"
                                    value={impersonateTargetUid}
                                    onChange={(e) => setImpersonateTargetUid(e.target.value)}
                                    placeholder="e.g. 5yX8vB9..."
                                    className="w-full bg-bg-elevated border border-border-strong rounded-xl py-3 pl-10 pr-4 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-brand/50 focus:border-brand transition-all font-mono"
                                />
                            </div>
                        </div>

                        <div className="bg-yellow-900/20 border border-yellow-500/30 p-3 rounded-lg flex items-start gap-3">
                            <Shield size={16} className="text-yellow-500 mt-0.5 shrink-0" />
                            <p className="text-[11px] text-yellow-200/80 leading-tight">
                                <span className="font-bold text-yellow-500 uppercase">Warning:</span> Impersonation sessions grant full organizational authority based on the target identity. Actions are logged to your real admin profile.
                            </p>
                        </div>
                    </div>

                    <div className="p-6 bg-bg-elevated/50 flex gap-3">
                        <button 
                            onClick={() => setShowImpersonateModal(false)}
                            className="flex-1 px-4 py-2.5 rounded-xl border border-border-strong text-text-primary text-sm font-bold hover:bg-bg-elevated transition-all"
                        >
                            CANCEL
                        </button>
                        <button 
                            onClick={() => handleImpersonate(impersonateTargetUid)}
                            disabled={!impersonateTargetUid.trim()}
                            className="flex-[2] bg-brand text-white text-sm font-bold py-2.5 rounded-xl hover:bg-brand-hover disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-brand/20 flex items-center justify-center gap-2"
                        >
                            <LogIn size={18} /> INITIATE SWAP
                        </button>
                    </div>
                </div>
            </div>
        );
    };

    const renderProfile = () => {
        if (!profile) return (
            <div className="flex items-center justify-center p-12">
                <RefreshCw className="animate-spin text-brand" size={32} />
            </div>
        );

        return (
            <div className="max-w-4xl mx-auto space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-500">
                {/* Header / Identity Card */}
                <div className="bg-bg-surface border border-border-subtle rounded-3xl p-8 relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-64 h-64 bg-brand/5 rounded-full -mr-32 -mt-32 blur-3xl group-hover:bg-brand/10 transition-colors"></div>
                    <div className="relative flex flex-col md:flex-row items-center gap-8">
                        <div className="w-24 h-24 rounded-2xl bg-brand/10 border-2 border-brand/20 flex items-center justify-center text-brand text-4xl font-bold shadow-xl shadow-brand/5">
                            {profile.firstName ? profile.firstName.charAt(0).toUpperCase() : (profile.email || '?').charAt(0).toUpperCase()}
                        </div>
                        <div className="flex-1 text-center md:text-left">
                            <h2 className="text-3xl font-black text-text-primary tracking-tight">
                                {profile.firstName || profile.lastName ? `${profile.firstName} ${profile.lastName}` : 'Anonymous Operative'}
                            </h2>
                            <div className="flex flex-wrap items-center justify-center md:justify-start gap-3 mt-2">
                                <span className="text-xs bg-bg-dark border border-border-strong px-3 py-1 rounded-full text-text-muted font-mono flex items-center gap-2">
                                    UID: <span className="text-brand font-bold">{profile.uid}</span>
                                    <button onClick={() => { navigator.clipboard.writeText(profile.uid); showToast('UID copied', 'success'); }} className="hover:text-brand transition-colors">
                                        <Copy size={12} />
                                    </button>
                                </span>
                                {profile.isEmailVerified ? (
                                    <span className="text-[10px] bg-green-500/10 text-green-400 border border-green-500/20 px-3 py-1 rounded-full font-bold uppercase tracking-wider flex items-center gap-1.5">
                                        <UserCheck size={12} /> Verified Identity
                                    </span>
                                ) : (
                                    <span className="text-[10px] bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 px-3 py-1 rounded-full font-bold uppercase tracking-wider flex items-center gap-1.5">
                                        <Lock size={12} /> Unverified
                                    </span>
                                )}
                            </div>
                        </div>
                    </div>
                </div>

                <div className="grid lg:grid-cols-2 gap-8">
                    {/* Basic Information */}
                    <div className="bg-bg-surface border border-border-subtle rounded-3xl p-6 space-y-6">
                        <div className="flex items-center gap-3 border-b border-border-strong pb-4">
                            <User className="text-brand" size={20} />
                            <h3 className="text-lg font-bold text-text-primary">Personal Details</h3>
                        </div>
                        <form onSubmit={(e) => {
                            e.preventDefault();
                            handleUpdateProfile(e.target.firstName.value, e.target.lastName.value, e.target.location.value);
                        }} className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-bold text-text-muted uppercase tracking-widest ml-1">First Name</label>
                                    <input name="firstName" defaultValue={profile.firstName} className="w-full bg-bg-dark border border-border-strong rounded-xl px-4 py-2.5 text-sm text-text-primary focus:border-brand focus:outline-none transition-all" />
                                </div>
                                <div className="space-y-1.5">
                                    <label className="text-[10px] font-bold text-text-muted uppercase tracking-widest ml-1">Last Name</label>
                                    <input name="lastName" defaultValue={profile.lastName} className="w-full bg-bg-dark border border-border-strong rounded-xl px-4 py-2.5 text-sm text-text-primary focus:border-brand focus:outline-none transition-all" />
                                </div>
                            </div>
                            <div className="space-y-1.5">
                                <label className="text-[10px] font-bold text-text-muted uppercase tracking-widest ml-1">Location</label>
                                <div className="relative">
                                    <MapPin className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" size={16} />
                                    <input name="location" defaultValue={profile.location} placeholder="e.g. Mumbai, India" className="w-full bg-bg-dark border border-border-strong rounded-xl pl-10 pr-4 py-2.5 text-sm text-text-primary focus:border-brand focus:outline-none transition-all" />
                                </div>
                            </div>
                            <button type="submit" disabled={isSubmitting} className="w-full bg-brand text-white font-bold py-3 rounded-xl hover:bg-brand-hover transition-all shadow-lg shadow-brand/10 disabled:opacity-50">
                                {isSubmitting ? 'SAVING...' : 'UPDATE PROFILE'}
                            </button>
                        </form>
                    </div>

                    {/* Account Security */}
                    <div className="bg-bg-surface border border-border-subtle rounded-3xl p-6 space-y-6">
                        <div className="flex items-center gap-3 border-b border-border-strong pb-4">
                            <Shield className="text-accent" size={20} />
                            <h3 className="text-lg font-bold text-text-primary">Identity Verification</h3>
                        </div>
                        
                        <div className="space-y-4">
                            <div className="p-4 bg-bg-dark rounded-2xl border border-border-strong">
                                <p className="text-[10px] font-bold text-text-muted uppercase tracking-widest mb-1">Registered Email</p>
                                <div className="flex items-center justify-between">
                                    <p className="text-sm text-text-primary font-mono">{profile.email}</p>
                                    {profile.isEmailVerified && <Mail className="text-green-400" size={16} />}
                                </div>
                            </div>

                            {!profile.isEmailVerified && (
                                <div className="space-y-4">
                                    {!isVerifying ? (
                                        <button onClick={handleSendVerificationEmail} disabled={isSubmitting} className="w-full bg-accent/10 border border-accent/30 text-accent font-bold py-3 rounded-xl hover:bg-accent/20 transition-all flex items-center justify-center gap-2">
                                            {isSubmitting ? ( <div className="w-4 h-4 border-2 border-accent/50 border-t-accent rounded-full animate-spin" /> ) : <Mail size={18} />}
                                            {isSubmitting ? 'SENDING...' : 'VERIFY EMAIL ADDRESS'}
                                        </button>
                                    ) : (
                                        <div className="space-y-4 animate-in slide-in-from-top-2 duration-300">
                                            <p className="text-xs text-text-muted">Enter the 6-digit code sent to <strong>{profile.email}</strong> to verify your identity.</p>
                                            <div className="flex gap-2">
                                                <input 
                                                    value={verificationCode}
                                                    onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                                    placeholder="000000"
                                                    className="flex-1 bg-bg-dark border border-border-strong rounded-xl px-4 py-2.5 text-center text-lg font-mono tracking-widest text-brand focus:border-brand focus:outline-none"
                                                />
                                                <button onClick={handleConfirmVerification} disabled={isSubmitting || verificationCode.length !== 6} className="bg-brand text-white font-bold px-6 rounded-xl hover:bg-brand-hover transition-all">
                                                    {isSubmitting ? '...' : 'CONFIRM'}
                                                </button>
                                            </div>
                                            <div className="flex justify-between items-center mt-2 px-1">
                                                <button 
                                                    onClick={handleSendVerificationEmail} 
                                                    disabled={isSubmitting || resendCooldown > 0} 
                                                    className={`text-[10px] uppercase font-bold tracking-widest ${resendCooldown > 0 ? 'text-text-muted cursor-not-allowed' : 'text-accent hover:text-accent-hover transition-colors'}`}
                                                >
                                                    {resendCooldown > 0 ? `Resend Code (${resendCooldown}s)` : 'Resend Code'}
                                                </button>
                                                <button onClick={() => setIsVerifying(false)} className="text-[10px] text-text-muted hover:text-text-primary transition-colors underline uppercase tracking-widest">
                                                    Cancel
                                                </button>
                                            </div>
                                        </div>
                                    )}
                                </div>
                            )}

                            {profile.isEmailVerified && (
                                <div className="flex flex-col items-center justify-center py-6 text-center space-y-2">
                                    <div className="w-16 h-16 rounded-full bg-green-500/10 border border-green-500/20 flex items-center justify-center text-green-400 mb-2 shadow-inner">
                                        <UserCheck size={32} />
                                    </div>
                                    <p className="text-sm font-bold text-text-primary">Identity Fully Secured</p>
                                    <p className="text-xs text-text-muted">Your sovereign ID is now cryptographically linked to your verified email.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                {/* Recent Activity */}
                <div className="bg-bg-surface border border-border-subtle rounded-3xl p-6 space-y-6">
                    <div className="flex justify-between items-center border-b border-border-strong pb-4">
                        <div className="flex items-center gap-3">
                            <History className="text-orange-400" size={20} />
                            <h3 className="text-lg font-bold text-text-primary">Recent Activity</h3>
                        </div>
                        <button onClick={fetchUserActivity} className="text-text-muted hover:text-brand transition-colors p-1" title="Refresh Activity">
                            <RefreshCw size={16} />
                        </button>
                    </div>

                    <div className="space-y-4 max-h-[400px] overflow-y-auto pr-2 custom-scrollbar">
                        {userActivity.length === 0 ? (
                            <div className="text-center py-8 text-text-muted">
                                <History size={32} className="mx-auto mb-3 opacity-20" />
                                <p className="text-sm">No recent activity found.</p>
                            </div>
                        ) : (
                            userActivity.map((log, idx) => (
                                <div key={idx} className="flex gap-4 p-4 rounded-xl border border-border-subtle hover:border-border-strong bg-bg-dark/50 transition-colors">
                                    <div className="mt-1">
                                        {/* Icon based on action */}
                                        {log.action === 'USER_LOGIN' && <LogIn size={16} className="text-brand" />}
                                        {(log.action === 'RESOURCE_CREATED' || log.action === 'Created') && <FileText size={16} className="text-green-400" />}
                                        {(log.action === 'RESOURCE_EDITED' || log.action === 'Edited') && <Edit2 size={16} className="text-yellow-400" />}
                                        {log.action === 'USER_ROLE_UPDATED' && <Shield size={16} className="text-red-400" />}
                                        {log.action === 'GROUP_JOINED' && <Users size={16} className="text-accent" />}
                                        {log.action === 'ORG_CREATED' && <Building size={16} className="text-blue-400" />}
                                        {log.action === 'GROUP_CREATED' && <Users size={16} className="text-purple-400" />}
                                        {log.action === 'ADMIN_IMPERSONATION' && <Zap size={16} className="text-yellow-500" />}
                                        {/* default */}
                                        {(!['USER_LOGIN', 'ORG_CREATED', 'GROUP_CREATED', 'RESOURCE_CREATED', 'Created', 'RESOURCE_EDITED', 'Edited', 'USER_ROLE_UPDATED', 'GROUP_JOINED', 'ADMIN_IMPERSONATION'].includes(log.action)) && <History size={16} className="text-text-muted" />}
                                    </div>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-1 sm:gap-4">
                                            <p className="text-sm font-bold text-text-primary uppercase tracking-wide truncate">
                                                {log.action.replace(/_/g, ' ')}
                                            </p>
                                            <p className="text-[10px] text-text-muted font-mono whitespace-nowrap shrink-0">
                                                {log.timestamp ? new Date(log.timestamp).toLocaleString() : 'Recent'}
                                            </p>
                                        </div>
                                        {log.details && typeof log.details === 'object' && Object.keys(log.details).filter(k => k !== 'password' && k !== 'code').length > 0 && (
                                            <div className="text-xs text-text-secondary mt-1.5 space-y-0.5 border-l-2 border-border-subtle pl-2 py-0.5">
                                                {Object.entries(log.details).filter(([k]) => k !== 'password' && k !== 'code').map(([k, v]) => (
                                                    <div key={k} className="truncate"><span className="opacity-50 lowercase">{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : String(v)}</div>
                                                ))}
                                            </div>
                                        )}
                                        {log.ipAddress && (
                                            <div className="text-[10px] text-text-muted/50 mt-2 border-t border-border-subtle pt-1 w-max">
                                                IP: {log.ipAddress}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            </div>
        );
    };

    const renderUsers = () => {
        return (
            <div className="space-y-6">
                <div className="flex justify-between items-center mb-6">
                    <h3 className="text-xl font-bold text-text-primary flex items-center gap-2">
                        <Users className="text-brand" /> Organization Members
                    </h3>
                    <div className="text-sm border border-border-strong px-3 py-1.5 rounded-md text-text-muted">
                        Total: <span className="text-brand font-bold">{orgMembers.length}</span>
                    </div>
                </div>

                <div className="grid gap-4">
                    {orgMembers.map(member => (
                        <div key={member.memberId} className="bg-bg-surface border justify-between border-border-subtle p-4 rounded-lg flex flex-col md:flex-row md:items-center gap-4 group">
                            <div className="flex items-center gap-4 flex-1">
                                <div className="w-10 h-10 rounded-full bg-brand/10 text-brand flex items-center justify-center font-bold font-mono border border-brand/20 shrink-0">
                                    {(member.name || '?').charAt(0).toUpperCase()}
                                </div>
                                <div>
                                    <p className="font-medium text-text-primary text-sm">{member.name}</p>
                                    <p className="text-xs text-text-muted font-mono">{member.email}</p>
                                </div>
                            </div>
                            <div className="flex flex-col md:flex-row items-start md:items-center gap-4">
                                <div className="flex gap-2 text-xs">
                                    <span className={`px-2 py-1 rounded-md border ${member.role === 'Owner' || member.role === 'Admin' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-bg-dark text-text-secondary border-border-strong'}`}>
                                        Base Role: {member.role}
                                    </span>
                                    {member.groupId && (
                                        <span className="px-2 py-1 rounded-md border bg-accent/10 border-accent/20 text-accent flex items-center gap-1">
                                            <Shield size={10} /> {orgGroups.find(g => g.id === member.groupId)?.name || 'Unknown Group'}
                                        </span>
                                    )}
                                </div>
                                {['Owner', 'Admin'].includes(currentUser?.role) && currentUser.uid !== member.uid && (
                                    <div className="flex items-center gap-2 mt-2 md:mt-0 opacity-100 md:opacity-0 group-hover:opacity-100 transition-opacity">
                                        {currentUser?.isSystemAdmin && !impersonatedUid && member.uid !== currentUser.uid && (
                                            <button 
                                                onClick={() => handleImpersonate(member.uid)}
                                                className="bg-brand/10 hover:bg-brand/20 text-brand border border-brand/20 p-1.5 rounded-md transition-colors"
                                                title="Impersonate User"
                                            >
                                                <User size={14} className="text-brand" />
                                            </button>
                                        )}
                                        <select 
                                            value={member.role}
                                            onChange={(e) => handleUpdateMember(member.memberId, e.target.value, member.groupId)}
                                            className="bg-bg-dark border border-border-strong text-xs px-2 py-1.5 rounded focus:border-brand outline-none"
                                        >
                                            <option value="Viewer">Viewer</option>
                                            <option value="Developer">Developer</option>
                                            <option value="Manager">Manager</option>
                                            <option value="Admin">Admin</option>
                                        </select>
                                        <select 
                                            value={member.groupId || ''}
                                            onChange={(e) => handleUpdateMember(member.memberId, member.role, e.target.value || null)}
                                            className="bg-bg-dark border border-border-strong text-xs px-2 py-1.5 rounded focus:border-accent outline-none"
                                        >
                                            <option value="">No Custom Group</option>
                                            {orgGroups.map(g => (
                                                <option key={g.id} value={g.id}>{g.name}</option>
                                            ))}
                                        </select>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))}
                    {orgMembers.length === 0 && (
                        <p className="text-center text-text-muted py-8 border border-dashed border-border-strong rounded-lg">No members found.</p>
                    )}
                </div>
            </div>
        );
    };

    const renderGroups = () => {
        return (
            <div className="space-y-6">
                <div className="flex justify-between items-center mb-6">
                    <h3 className="text-xl font-bold text-text-primary flex items-center gap-2">
                        <Shield className="text-accent" /> Custom Privilege Groups
                    </h3>
                    {['Admin', 'Owner'].includes(currentUser?.role) && (
                        <button onClick={() => setIsCreating(true)} className="bg-accent hover:bg-accent/80 text-white text-sm font-medium px-4 py-1.5 rounded-md flex items-center gap-2 transition-colors">
                            <Plus size={16} /> New Group
                        </button>
                    )}
                </div>

                {isCreating && (
                    <div className="bg-bg-surface border border-accent/50 p-6 rounded-lg mb-6 animate-in fade-in slide-in-from-top-4 duration-300">
                        <div className="flex justify-between items-center mb-4">
                            <h4 className="font-bold text-text-primary">Create Security Group</h4>
                            <button onClick={() => setIsCreating(false)} className="text-text-muted hover:text-text-primary"><X size={18} /></button>
                        </div>
                        <form onSubmit={(e) => {
                            e.preventDefault();
                            const privs = {};
                            PRIVILEGES.forEach(p => { privs[p] = e.target[p].checked; });
                            handleCreateGroup({ name: e.target.name.value, privileges: privs });
                            setIsCreating(false);
                        }} className="space-y-4">
                            <input name="name" placeholder="Group Name (e.g. DBA Team)" required className="w-full max-w-sm bg-bg-dark border border-border-strong rounded-md px-3 py-2 text-sm focus:border-accent outline-none mb-2" />
                            
                            <p className="text-xs text-text-muted uppercase tracking-wider mb-2">Assign Privileges</p>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-bg-dark p-4 rounded-md border border-border-strong">
                                {PRIVILEGES.map(priv => (
                                    <label key={priv} className="flex items-center gap-2 cursor-pointer text-sm text-text-secondary hover:text-text-primary">
                                        <input type="checkbox" name={priv} className="accent-brand w-4 h-4 cursor-pointer" />
                                        {priv}
                                    </label>
                                ))}
                            </div>
                            <div className="flex justify-end pt-2">
                                <button type="submit" className="bg-accent text-white text-sm font-medium px-6 py-2 rounded-md hover:bg-accent/80 transition-colors">Confirm Creation</button>
                            </div>
                        </form>
                    </div>
                )}

                <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {orgGroups.map(group => (
                        <div key={group.id} onClick={() => setSelectedGroupDetail(group)} className="bg-bg-surface border border-border-subtle p-5 rounded-lg flex flex-col group/card hover:border-accent/50 cursor-pointer transition-colors relative">
                            <div className="flex items-center justify-between mb-4 border-b border-border-strong pb-3">
                                <div className="flex items-center gap-2.5">
                                    <div className="w-8 h-8 rounded bg-bg-elevated border border-border-strong flex items-center justify-center text-accent">
                                        <Shield size={16} />
                                    </div>
                                    <h4 className="font-bold text-text-primary">{group.name}</h4>
                                </div>
                                {['Owner', 'Admin'].includes(currentUser?.role) && (
                                    <button onClick={(e) => { e.stopPropagation(); handleDeleteGroup(group.id); }} className="text-text-muted hover:text-red-400 opacity-0 group-hover/card:opacity-100 transition-opacity">
                                        <X size={16} />
                                    </button>
                                )}
                            </div>
                            
                            <div className="flex-1">
                                <p className="text-xs text-text-muted uppercase tracking-wider mb-3">Active Capabilities</p>
                                <div className="flex flex-wrap gap-1.5">
                                    {PRIVILEGES.map(priv => group.privileges[priv] ? (
                                        <span key={priv} className="bg-brand/10 text-brand border border-brand/20 px-2 py-0.5 rounded text-[10px] uppercase font-medium tracking-wide">
                                            {priv}
                                        </span>
                                    ) : null)}
                                </div>
                            </div>
                            
                            {['Owner', 'Admin'].includes(currentUser?.role) && (
                                <div className="mt-4 pt-3 border-t border-border-subtle opacity-0 group-hover/card:opacity-100 transition-opacity flex justify-between items-center">
                                    <p className="text-[10px] text-text-muted text-center">To edit, delete & recreate.</p>
                                    <button onClick={(e) => { e.stopPropagation(); setAssigningGroup(group); }} className="text-xs text-brand hover:text-brand-hover hover:underline transition-colors flex items-center gap-1">
                                        <Users size={12} /> Assign Members
                                    </button>
                                </div>
                            )}
                        </div>
                    ))}
                    {orgGroups.length === 0 && !isCreating && (
                        <div className="col-span-full py-12 text-center border border-dashed border-border-strong rounded-xl text-text-muted">
                            <Shield size={32} className="mx-auto mb-3 opacity-30" />
                            <p className="text-sm">No custom groups engineered for this context.</p>
                        </div>
                    )}
                </div>

                {assigningGroup && (
                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                        <div className="bg-bg-surface border border-border-strong rounded-xl p-6 w-full max-w-lg shadow-2xl animate-in fade-in zoom-in-95 duration-200">
                            <div className="flex justify-between items-center mb-6">
                                <h3 className="text-xl font-bold text-text-primary flex items-center gap-2">
                                    <Users className="text-accent" size={20} /> Assign Members: {assigningGroup.name}
                                </h3>
                                <button onClick={() => setAssigningGroup(null)} className="text-text-muted hover:text-text-primary bg-bg-elevated p-1.5 rounded-md"><X size={16} /></button>
                            </div>
                            
                            <form onSubmit={async (e) => {
                                e.preventDefault();
                                const formData = new FormData(e.target);
                                const selectedUids = formData.getAll('members');
                                
                                setIsSubmitting(true);
                                try {
                                    for (const member of orgMembers) {
                                        const shouldBeInGroup = selectedUids.includes(member.uid);
                                        const isInGroup = member.groupId === assigningGroup.id;
                                        
                                        if (shouldBeInGroup && !isInGroup) {
                                            await fetchWithAuth(`/org-members/${member.memberId}`, firebaseUser, { method: 'PUT', body: JSON.stringify({ groupId: assigningGroup.id }) });
                                        } else if (!shouldBeInGroup && isInGroup) {
                                            await fetchWithAuth(`/org-members/${member.memberId}`, firebaseUser, { method: 'PUT', body: JSON.stringify({ groupId: null }) });
                                        }
                                    }
                                    showToast('Group members synchronized', 'success');
                                    fetchOrgMembers(currentOrg.id);
                                    setAssigningGroup(null);
                                } catch (err) {
                                    showToast(err.message, 'error');
                                } finally {
                                    setIsSubmitting(false);
                                }
                            }}>
                                <div className="space-y-2 max-h-64 overflow-y-auto pr-2 mb-6">
                                    {orgMembers.map(member => {
                                        const isChecked = member.groupId === assigningGroup.id;
                                        const isOtherGroup = member.groupId && member.groupId !== assigningGroup.id;
                                        
                                        return (
                                            <label key={member.uid} className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${isChecked ? 'bg-accent/10 border-accent/50' : 'bg-bg-dark border-border-strong hover:border-text-muted'}`}>
                                                <input type="checkbox" name="members" value={member.uid} defaultChecked={isChecked} className="accent-brand w-4 h-4" />
                                                <div className="flex-1">
                                                    <div className="text-sm font-medium text-text-primary">{member.name}</div>
                                                    <div className="text-xs text-text-muted">{member.email} {isOtherGroup && <span className="text-orange-400 opacity-80">(Will be unassigned from current group)</span>}</div>
                                                </div>
                                            </label>
                                        );
                                    })}
                                    {orgMembers.length === 0 && <p className="text-sm text-text-muted italic">No members available to assign.</p>}
                                </div>
                                <div className="flex gap-3 border-t border-border-strong pt-4">
                                    <button type="button" onClick={() => setAssigningGroup(null)} disabled={isSubmitting} className="flex-1 bg-bg-dark hover:bg-bg-elevated border border-border-strong text-text-primary text-sm font-medium py-2 rounded-md transition-colors disabled:opacity-50">Cancel</button>
                                    <button type="submit" disabled={isSubmitting} className="flex-1 bg-accent text-white text-sm font-medium py-2 rounded-md hover:bg-accent/80 transition-colors flex justify-center items-center gap-2 disabled:opacity-50">
                                        {isSubmitting ? <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></span> : 'Save Assignments'}
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                )}
                
                {selectedGroupDetail && (
                    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                        <div className="bg-bg-surface border border-border-strong rounded-xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl animate-in zoom-in-95 duration-200">
                            {/* Modal Header */}
                            <div className="p-6 border-b border-border-subtle shrink-0 bg-bg-elevated rounded-t-xl text-center relative group/header">
                                <button
                                    onClick={() => setSelectedGroupDetail(null)}
                                    className="absolute right-4 top-4 text-text-muted hover:text-text-primary bg-bg-dark rounded p-1"
                                >
                                    <X size={20} />
                                </button>
                                <div className="flex justify-center mb-3">
                                    <div className="w-16 h-16 rounded-full bg-accent/10 flex items-center justify-center text-accent border-2 border-accent/20">
                                        <Shield size={32} />
                                    </div>
                                </div>
                                <h2 className="text-2xl font-bold text-text-primary capitalize mb-2">
                                    {selectedGroupDetail.name}
                                </h2>
                                <div className="flex flex-wrap justify-center gap-1.5 mt-2">
                                    <span className="text-xs text-text-muted mr-2">Privileges:</span>
                                    {PRIVILEGES.map(priv => selectedGroupDetail.privileges[priv] ? (
                                        <span key={priv} className="bg-brand/10 text-brand border border-brand/20 px-2 py-0.5 rounded text-[10px] uppercase font-medium tracking-wide">
                                            {priv}
                                        </span>
                                    ) : null)}
                                </div>
                            </div>

                            {/* Modal Body */}
                            <div className="flex-1 overflow-y-auto p-6 space-y-8 bg-bg-dark rounded-b-xl">
                                
                                {/* Members Section */}
                                <div>
                                    <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                                        <Users className="text-brand" size={18} /> Group Members
                                    </h3>
                                    <div className="border border-border-strong rounded-lg overflow-hidden bg-bg-surface">
                                        <table className="w-full text-sm text-left">
                                            <thead className="text-xs text-text-muted uppercase bg-bg-elevated border-b border-border-strong">
                                                <tr>
                                                    <th className="px-4 py-3 font-medium">User</th>
                                                    <th className="px-4 py-3 font-medium">Email</th>
                                                    <th className="px-4 py-3 font-medium">Base Role</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {orgMembers.filter(m => m.groupId === selectedGroupDetail.id).length > 0 ? (
                                                    orgMembers.filter(m => m.groupId === selectedGroupDetail.id).map(member => (
                                                        <tr key={member.uid} className="border-b border-border-subtle last:border-0 hover:bg-bg-elevated/50 transition-colors">
                                                            <td className="px-4 py-3 font-medium text-text-primary flex items-center gap-2">
                                                                <div className="w-6 h-6 rounded-full bg-brand/10 text-brand flex items-center justify-center text-[10px] font-bold border border-brand/20">
                                                                    {(member.name || '?').charAt(0).toUpperCase()}
                                                                </div>
                                                                {member.name}
                                                            </td>
                                                            <td className="px-4 py-3 text-text-secondary font-mono text-xs">{member.email}</td>
                                                            <td className="px-4 py-3 text-text-secondary">
                                                                <span className={`px-2 py-1 rounded text-[10px] uppercase font-bold tracking-wider border ${member.role === 'Owner' || member.role === 'Admin' ? 'bg-red-500/10 text-red-400 border-red-500/20' : 'bg-bg-dark border-border-strong text-text-muted'}`}>
                                                                    {member.role}
                                                                </span>
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="3" className="px-4 py-8 text-center text-text-muted italic">
                                                            No members assigned to this group.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>

                                {/* Assigned Tasks/Provisions Section */}
                                <div>
                                    <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                                        <Folder className="text-accent" size={18} /> Available Provisions / Tasks
                                    </h3>
                                    <div className="border border-border-strong rounded-lg overflow-hidden bg-bg-surface">
                                        <table className="w-full text-sm text-left">
                                            <thead className="text-xs text-text-muted uppercase bg-bg-elevated border-b border-border-strong">
                                                <tr>
                                                    <th className="px-4 py-3 font-medium">Provision Name</th>
                                                    <th className="px-4 py-3 font-medium">Type</th>
                                                    <th className="px-4 py-3 font-medium">Access Level</th>
                                                    <th className="px-4 py-3 font-medium">Other Groups</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                {resources.filter(r => r.allowedGroups?.includes(selectedGroupDetail.id)).length > 0 ? (
                                                    resources.filter(r => r.allowedGroups?.includes(selectedGroupDetail.id)).map(res => (
                                                        <tr key={res.id} className="border-b border-border-subtle last:border-0 hover:bg-bg-elevated/50 transition-colors">
                                                            <td className="px-4 py-3 font-medium text-text-primary">{res.name}</td>
                                                            <td className="px-4 py-3">
                                                                <span className="px-2 py-1 bg-accent/10 text-accent text-[10px] uppercase tracking-wider font-bold rounded border border-accent/20">
                                                                    {res.type}
                                                                </span>
                                                            </td>
                                                            <td className="px-4 py-3 text-text-secondary capitalize">{res.accessLevel}</td>
                                                            <td className="px-4 py-3 text-text-secondary text-xs truncate max-w-[200px]">
                                                                {res.allowedGroups
                                                                    .filter(gid => gid !== selectedGroupDetail.id)
                                                                    .map(gid => orgGroups.find(g => g.id === gid)?.name || gid)
                                                                    .join(', ') || <span className="text-text-muted italic">None</span>}
                                                            </td>
                                                        </tr>
                                                    ))
                                                ) : (
                                                    <tr>
                                                        <td colSpan="4" className="px-4 py-8 text-center text-text-muted italic">
                                                            No provisions explicitly assigned to this group.
                                                        </td>
                                                    </tr>
                                                )}
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                                
                            </div>
                        </div>
                    </div>
                )}
            </div>
        );
    };

    return (
        <div className="min-h-screen bg-bg-dark flex flex-col md:flex-row">
            {/* Sidebar */}
            {/* Sidebar Navigation */}
            <aside className="w-full md:w-64 bg-bg-surface border-r border-border-subtle flex flex-col h-full z-20">
                <div className="p-6 border-b border-border-subtle">
                    <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-brand rounded-xl flex items-center justify-center shadow-lg shadow-brand/20">
                            <Shield className="text-white" size={24} />
                        </div>
                        <div>
                            <h1 className="text-lg font-bold text-text-primary tracking-tight">NexusGuard</h1>
                            <p className="text-[10px] text-brand uppercase font-bold tracking-widest">Enterprise Security</p>
                        </div>
                    </div>
                </div>

                <div className="flex-1 overflow-y-auto p-4 custom-scrollbar">
                    <div className="bg-bg-dark p-4 rounded-xl border border-border-strong shadow-inner mb-6 flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-bg-surface flex items-center justify-center font-bold text-brand border border-border-strong shadow-sm">
                            {(currentUser?.name || '?').charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                            <p className="text-sm font-bold text-text-primary truncate">{currentUser?.name}</p>
                            <p className="text-[10px] text-text-muted flex items-center gap-1 font-semibold uppercase tracking-tighter">
                                {currentUser?.role === 'Owner' && <Shield size={10} className="text-brand" />}
                                {currentUser?.role}
                            </p>
                        </div>
                    </div>

                    <nav className="space-y-4">
                        {[
                            { id: 'resources', label: 'Provision Hub', icon: Database },
                            { id: 'details', label: 'Org Context', icon: Building },
                            { id: 'users', label: 'Identities', icon: Users },
                            { id: 'groups', label: 'Security Groups', icon: Lock },
                            { id: 'profile', label: 'My Profile', icon: User },
                        ].map(item => (
                            <button
                                key={item.id}
                                onClick={() => setActiveTab(item.id)}
                                className={`w-full flex items-center gap-4 px-4 py-3 rounded-lg transition-all group ${
                                    activeTab === item.id 
                                    ? 'bg-brand/10 text-brand border border-brand/20 shadow-sm' 
                                    : 'text-text-secondary hover:bg-bg-elevated hover:text-text-primary'
                                }`}
                            >
                                <item.icon size={20} className={activeTab === item.id ? 'text-brand' : 'text-text-muted group-hover:text-text-primary'} />
                                <span className="text-sm font-semibold">{item.label}</span>
                                {activeTab === item.id && <div className="ml-auto w-1.5 h-1.5 rounded-full bg-brand shadow-[0_0_8px_rgba(var(--brand-rgb),0.6)]"></div>}
                            </button>
                        ))}

                        {(hasPrivilege('INFRASTRUCTURE') || currentUser?.role === 'Owner') && (
                            <button onClick={() => setActiveTab('infra')}
                                className={`w-full flex items-center gap-4 px-4 py-3 rounded-lg transition-all group ${
                                    activeTab === 'infra' 
                                    ? 'bg-brand/10 text-brand border border-brand/20 shadow-sm' 
                                    : 'text-text-secondary hover:bg-bg-elevated hover:text-text-primary'
                                }`}>
                                <Server size={20} className={activeTab === 'infra' ? 'text-brand' : 'text-text-muted group-hover:text-text-primary'} />
                                <span className="text-sm font-semibold">Infra Nodes</span>
                            </button>
                        )}

                        {currentUser?.role === 'Owner' && (
                            <button onClick={() => setActiveTab('matrix')}
                                className={`w-full flex items-center gap-4 px-4 py-3 rounded-lg transition-all group ${
                                    activeTab === 'matrix' 
                                    ? 'bg-brand/10 text-brand border border-brand/20 shadow-sm' 
                                    : 'text-text-secondary hover:bg-bg-elevated hover:text-text-primary'
                                }`}>
                                <div className={activeTab === 'matrix' ? 'text-brand' : 'text-text-muted group-hover:text-text-primary'}>
                                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="3" y1="15" x2="21" y2="15"></line><line x1="9" y1="3" x2="9" y2="21"></line><line x1="15" y1="3" x2="15" y2="21"></line></svg>
                                </div>
                                <span className="text-sm font-semibold">Access Matrix</span>
                            </button>
                        )}

                        {(hasPrivilege('EXECUTE') || currentUser?.role === 'Owner') && (
                            <button onClick={() => setActiveTab('terminal')}
                                className={`w-full flex items-center gap-4 px-4 py-3 rounded-lg transition-all group ${
                                    activeTab === 'terminal' 
                                    ? 'bg-brand/10 text-brand border border-brand/20 shadow-sm' 
                                    : 'text-text-secondary hover:bg-bg-elevated hover:text-text-primary'
                                }`}>
                                <Terminal size={20} className={activeTab === 'terminal' ? 'text-brand' : 'text-text-muted group-hover:text-text-primary'} />
                                <span className="text-sm font-semibold">Terminal</span>
                            </button>
                        )}

                        {['Admin', 'Owner'].includes(currentUser?.role) && (
                            <button onClick={() => { setActiveTab('approvals'); fetchPendingRequests(currentOrg?.id); }}
                                className={`w-full flex items-center gap-4 px-4 py-3 rounded-lg transition-all group relative ${
                                    activeTab === 'approvals' 
                                    ? 'bg-brand/10 text-brand border border-brand/20 shadow-sm' 
                                    : 'text-text-secondary hover:bg-bg-elevated hover:text-text-primary'
                                }`}>
                                <UserPlus size={20} className={activeTab === 'approvals' ? 'text-brand' : 'text-text-muted group-hover:text-text-primary'} />
                                <span className="text-sm font-semibold">Approvals</span>
                                {pendingRequests.length > 0 && (
                                    <span className="ml-auto bg-red-500 text-white text-[10px] font-bold px-2 py-0.5 rounded-full shadow-lg shadow-red-500/30">{pendingRequests.length}</span>
                                )}
                            </button>
                        )}
                    </nav>
                </div>

                <div className="p-4 mt-auto border-t border-border-subtle bg-bg-surface/50 backdrop-blur-sm">
                    {/* Theme Toggle */}
                    <button 
                        onClick={toggleTheme}
                        className="w-full flex items-center justify-between px-4 py-3 bg-bg-dark border border-border-strong rounded-xl hover:border-brand/40 transition-all group mb-6 shadow-inner"
                    >
                        <div className="flex items-center gap-3">
                            <div className={`p-1.5 rounded-lg transition-colors ${theme === 'dark' ? 'bg-accent/10 text-accent' : 'bg-yellow-500/10 text-yellow-500'}`}>
                                {theme === 'dark' ? <Moon size={16} /> : <Sun size={16} />}
                            </div>
                            <span className="text-xs font-bold text-text-primary uppercase tracking-tight">{theme === 'dark' ? 'Night Shift' : 'Solstice'}</span>
                        </div>
                        <div className={`w-9 h-5 rounded-full relative transition-all duration-500 ${theme === 'dark' ? 'bg-accent/40' : 'bg-yellow-100'}`}>
                            <div className={`absolute top-1 w-3 h-3 rounded-full transition-all duration-500 shadow-sm ${theme === 'dark' ? 'right-1 bg-accent scale-110' : 'left-1 bg-yellow-500'}`}></div>
                        </div>
                    </button>

                    <div className="flex flex-col gap-3">
                        <button onClick={handleSwitchOrg}
                            className="w-full flex items-center gap-3 px-3 py-2.5 text-text-muted hover:text-accent hover:bg-accent/5 rounded-lg transition-all group font-medium">
                            <Globe size={18} className="group-hover:rotate-12 transition-transform" />
                            <span className="text-xs uppercase tracking-widest font-bold">Switch Realm</span>
                        </button>

                        {currentUser?.isSystemAdmin && (
                            <button onClick={() => setShowImpersonateModal(true)}
                                className="w-full flex items-center gap-3 px-3 py-2.5 text-text-muted hover:text-brand hover:bg-brand/5 rounded-lg transition-all group font-medium">
                                <Zap size={18} className="group-hover:scale-110 transition-transform text-brand/60 group-hover:text-brand" />
                                <span className="text-xs uppercase tracking-widest font-bold">Impersonate</span>
                            </button>
                        )}

                        <button onClick={handleLogout}
                            className="w-full flex items-center gap-3 px-3 py-2.5 text-text-muted hover:text-red-400 hover:bg-red-400/5 rounded-lg transition-all group font-medium">
                            <LogOut size={18} className="group-hover:translate-x-0.5 transition-transform" />
                            <span className="text-xs uppercase tracking-widest font-bold">Disconnect</span>
                        </button>
                    </div>
                </div>
            </aside>

            {/* Main Content */}
            <main className="flex-1 flex flex-col h-screen overflow-hidden">
                {['Admin', 'Owner'].includes(currentUser?.role) && pendingRequests.length > 0 && activeTab !== 'approvals' && (
                    <div className="bg-brand/10 border-b border-brand/20 p-4 flex items-center justify-between shrink-0">
                        <div className="flex items-center gap-2 text-brand text-sm font-medium">
                            <span className="relative flex h-3 w-3">
                                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-brand opacity-75"></span>
                                <span className="relative inline-flex rounded-full h-3 w-3 bg-brand"></span>
                            </span>
                            {pendingRequests.length} Pending Join Request{pendingRequests.length > 1 ? 's' : ''}
                        </div>
                        <button onClick={() => { setActiveTab('approvals'); }}
                            className="text-brand hover:text-brand-hover text-sm font-medium underline transition-colors">
                            Review â†’
                        </button>
                    </div>
                )}

                <div className="flex-1 overflow-y-auto p-6 md:p-8">
                    {impersonatedUid && (
                        <div className="max-w-6xl mx-auto mb-6 bg-brand/20 border border-brand/40 p-4 rounded-xl flex items-center justify-between animate-pulse">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-brand/20 rounded-lg">
                                    <User className="text-brand" size={20} />
                                </div>
                                <div>
                                    <p className="text-sm font-bold text-text-primary uppercase tracking-tight">Active Impersonation Session</p>
                                    <p className="text-xs text-text-muted">You are acting as user <span className="text-brand font-mono">{impersonatedUid}</span></p>
                                </div>
                            </div>
                            <button 
                                onClick={stopImpersonating}
                                className="bg-brand text-white text-xs font-bold px-4 py-2 rounded-lg hover:bg-brand-hover transition-all flex items-center gap-2"
                            >
                                <X size={14} /> STOP IMPERSONATING
                            </button>
                        </div>
                    )}
                    <div className="max-w-6xl mx-auto">
                        {activeTab === 'resources' && renderResources()}
                        {activeTab === 'matrix' && renderMatrix()}
                        {activeTab === 'terminal' && renderTerminal()}
                        {activeTab === 'details' && renderOrgDetails()}
                        {activeTab === 'users' && renderUsers()}
                        {activeTab === 'groups' && renderGroups()}
                        {activeTab === 'profile' && renderProfile()}
                        {activeTab === 'infra' && (
                            <div className="flex flex-col items-center justify-center p-12 text-center text-text-muted h-full border border-dashed border-border-strong rounded-lg">
                                <Server size={48} className="mb-4 text-brand opacity-80" />
                                <h3 className="text-xl font-medium mb-2 text-text-primary">Infrastructure Provisioning</h3>
                                <p className="max-w-md">Live Redis and PostgreSQL database provisioning module. Your INFRASTRUCTURE privileges allow managing cloud hardware nodes.</p>
                            </div>
                        )}
                        {activeTab === 'approvals' && (
                            <div className="space-y-4">
                                <div className="flex items-center gap-3 mb-6">
                                    <UserPlus className="text-brand" size={24} />
                                    <h3 className="text-xl font-bold text-text-primary">Join Request Approvals</h3>
                                </div>
                                {pendingRequests.length > 0 ? (
                                    <div className="space-y-3">
                                        {pendingRequests.map(req => (
                                            <div key={req.id} className="flex flex-col gap-3 p-4 bg-bg-surface border border-border-subtle rounded-lg">
                                                <div className="flex items-center justify-between">
                                                    <div className="flex items-center gap-4">
                                                        <div className="w-10 h-10 rounded-full bg-yellow-500/10 border border-yellow-500/30 flex items-center justify-center text-yellow-400 font-bold shrink-0">
                                                            {(req.displayName || req.email || '?').charAt(0).toUpperCase()}
                                                        </div>
                                                        <div>
                                                            <p className="text-sm font-medium text-text-primary">{req.displayName || 'Unknown User'}</p>
                                                            <p className="text-xs text-text-muted">{req.email}</p>
                                                            <div className="flex items-center gap-2 mt-1">
                                                                <span className="text-[10px] bg-bg-dark text-text-muted px-2 py-0.5 rounded border border-border-strong">
                                                                    Requested: <span className="text-accent font-medium">{req.requestedRole || 'Viewer'}</span>
                                                                </span>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <div className="bg-bg-dark rounded p-3 text-sm text-text-secondary border border-border-strong break-words">
                                                    <span className="text-xs text-text-muted block mb-1 uppercase tracking-wider font-semibold">Work Details / Reason</span>
                                                    {req.workDetails || 'No details provided.'}
                                                </div>

                                                <div className="flex items-center justify-end gap-6 mt-2 pt-3 border-t border-border-subtle">
                                                    <form onSubmit={(e) => {
                                                        e.preventDefault();
                                                        handleApproveRequest(req.id, e.target.assignedRole.value);
                                                    }} className="flex items-center gap-4">
                                                        <select name="assignedRole" defaultValue={req.requestedRole || 'Viewer'}
                                                            className="bg-bg-dark border border-border-strong rounded px-2 py-1.5 text-xs text-text-primary focus:outline-none focus:border-accent">
                                                            <option value="Viewer">Viewer</option>
                                                            <option value="Developer">Developer</option>
                                                            <option value="Manager">Manager</option>
                                                        </select>
                                                        <button type="submit"
                                                            className="flex items-center gap-1.5 bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/20 px-3 py-1.5 rounded-md text-sm font-medium transition-colors">
                                                            <Check size={14} /> Approve
                                                        </button>
                                                    </form>
                                                    <button onClick={() => handleDenyRequest(req.id)}
                                                        className="flex items-center gap-1.5 bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20 px-3 py-1.5 rounded-md text-sm font-medium transition-colors">
                                                        <X size={14} /> Deny
                                                    </button>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                ) : (
                                    <div className="flex flex-col items-center justify-center p-12 text-center border border-dashed border-border-strong rounded-lg">
                                        <Check size={48} className="mb-4 text-green-400 opacity-60" />
                                        <h3 className="text-lg font-medium mb-2 text-text-primary">All Clear</h3>
                                        <p className="text-sm text-text-muted">No pending join requests for this organization.</p>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            </main>

            {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}
            {renderImpersonateModal()}
        </div>
    );
}
