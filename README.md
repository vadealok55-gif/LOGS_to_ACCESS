# NexusGuard - Resource Hub & Provisioning Platform

![NexusGuard Logo](https://via.placeholder.com/1200x300?text=NexusGuard+Platform)

**NexusGuard** is a secure, modular platform designed for managing organizational resources (e.g., servers, databases, files, infrastructure provisions) with a rigorous **Role-Based Access Control (RBAC)** architecture that employs an advanced **Access Control Matrix (ACM)** to determine precise privileges.

At its core, NexusGuard acts as a secure "Resource Hub" where users can browse, provision, and manage infrastructure or documents. It is built to ensure that least privilege is strictly enforced while maintaining a smooth and dynamic user experience.

---

## 📑 Table of Contents
1. [Key Features](#-key-features)
2. [Technology Stack](#-technology-stack)
3. [Architecture Overview](#-architecture-overview)
4. [Access Control Matrix (ACM)](#-access-control-matrix-acm)
5. [The Staging Workflow Algorithm](#-the-staging-workflow-algorithm)
6. [Project Structure](#-project-structure)
7. [API Endpoints Overview](#-api-endpoints-overview)
8. [Audit Logging System](#-audit-logging-system)
9. [Installation & Setup](#-installation--setup)
10. [Configuration (Environment Variables)](#-configuration-environment-variables)
11. [Firebase Setup](#-firebase-setup)
12. [Hardware Requirements](#-hardware-requirements)
13. [Contributing](#-contributing)
14. [License](#-license)

---

## 🌟 Key Features

- **Robust Authentication:** Secure authentication via Firebase Auth (Email/Password or Google OAuth).
- **Advanced RBAC:** Highly granular Role-Based Access Control using an Access Control Matrix.
- **Resource Provisioning:** Create, manage, and delete resources with strict access constraints.
- **Approval Workflow (Staging):** Built-in staging area where resources created by non-admins must be approved before going live.
- **System Admin Impersonation:** Administrators can impersonate other users to view the platform exactly as they see it without needing their credentials.
- **Custom Groups:** Create custom groups and assign specific privileges that override standard roles.
- **Granular Provision Rules:** Grant access to specific resources at the user or group level.
- **Immutable Audit Logging:** Every mutating request (POST, PUT, DELETE) is intercepted by custom middleware and written to an unalterable audit log.
- **Email Verification & Outbound Comms:** Integrated EmailJS for secure communication.
- **Modern UI/UX:** Responsive, dynamic, and beautiful interface built with React, Tailwind CSS, and Lucide Icons.

---

## 💻 Technology Stack

### Frontend (User Interface)
- **Framework:** React.js
- **Build Tool:** Vite
- **Routing:** React Router DOM
- **Styling:** Tailwind CSS
- **Icons:** Lucide React
- **External Comms:** EmailJS Browser SDK (for outbound verification emails)

### Backend (Server API & Security)
- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** Firebase Firestore (NoSQL Document Store)
- **Authentication:** Firebase Admin SDK (JWT Validation)
- **Security Middleware:** Helmet, CORS
- **Environment Config:** dotenv

---

## 🏗 Architecture Overview

The application follows a decoupled client-server architecture:

1. **Client Layer:** A React SPA served via Vite. It communicates directly with Firebase Auth for authentication, but relies on the custom Express backend for all resource and organization management to ensure security constraints are met.
2. **API Layer:** An Express.js REST API that intercepts requests, validates JWTs, enforces the Access Control Matrix, and writes audit logs before executing operations on the database.
3. **Data Layer:** Firestore NoSQL database that houses Users, Organizations, Members, Groups, Resources, Pending Provisions (Staging), and Activity Logs.
4. **Security Layer:** Custom Firestore security rules (`firestore.rules`) prevent unauthorized direct access from the client, forcing all mutating operations through the secure backend API.

---

## 🛡 Access Control Matrix (ACM)

The Access Control Matrix operates at multiple layers to provide both broad organizational access and granular, resource-level security.

### 1. The Global Privilege Matrix
Access to generic actions is determined by standard organizational roles:

| Role / Privilege   | READ | WRITE | DELETE | EXECUTE | BILLING | NETWORK | INFRASTRUCTURE |
|--------------------|:----:|:-----:|:------:|:-------:|:-------:|:-------:|:--------------:|
| **Owner / Admin**  |  ✅   |  ✅    |   ✅    |   ✅     |   ✅     |   ✅     |       ✅        |
| **Manager**        |  ✅   |  ✅    |   ✅    |   ❌     |   ❌     |   ❌     |       ❌        |
| **Developer**      |  ✅   |  ✅    |   ❌    |   ❌     |   ❌     |   ❌     |       ❌        |
| **Viewer**         |  ✅   |  ❌    |   ❌    |   ❌     |   ❌     |   ❌     |       ❌        |

### 2. The Resource-Level Matrix (Granular Overrides)
Once a resource is active, the matrix becomes granular. Resource documents enforce access based on:
- **allowedRoles**: Standard roles permitted to access/edit.
- **allowedGroups**: Custom groups permitted to access/edit.
- **provisionRoles (User Overrides)**: Explicit user-level grants (`Administration`, `Editor`, `Viewer`).
- **provisionGroupRoles (Group Overrides)**: Explicit group-level grants.

### 3. Execution Pipeline for Resource Editing
When a user updates a resource, the backend verifies access in this exact order:
1. Is the user a **System Admin**? -> `GRANT`
2. Is the user the **Owner or Admin** of the Organization? -> `GRANT`
3. Does the user's **Group** have a custom `WRITE` privilege?
   - If yes, is the user's group in `allowedGroups`? -> `GRANT`
4. Is the user explicitly listed in **`provisionRoles`** as `Editor` or `Administration`? -> `GRANT`
5. If none match -> `DENY (403 Forbidden)`

---

## 🔒 Advanced Cyber Security Mechanisms: Staging & Impersonation

NexusGuard incorporates specialized security workflows designed to mitigate insider threats, prevent unauthorized infrastructure sprawl, and facilitate secure administrative oversight.

### 1. The Staging Workflow Algorithm (Approval Workflow)
In a cybersecurity context, allowing any user with `WRITE` access to directly provision infrastructure creates significant risk for misconfigurations, cost overruns, and security vulnerabilities (e.g., creating a public-facing database by mistake). NexusGuard prevents this via an isolated **Staging Area**:
- **Strict Separation of Duties (SoD):** The platform enforces a Maker-Checker principle. A Developer or Manager (Maker) can draft and request a new resource, but they cannot authorize its deployment.
- **Traffic Interception:** When a non-Admin attempts to create a resource, the API intercepts the payload and diverts it to a `pending_provisions` collection, ensuring it is technically impossible for the resource to impact the live production environment.
- **Admin Authorization (Checker):** An Owner or System Administrator must review the staged resource's parameters (e.g., access level, requested roles). Only upon explicit approval does the backend migrate the resource to the live `resources` collection.
- **Threat Mitigation:** This prevents "shadow IT" and malicious or accidental deployment of vulnerable infrastructure by enforcing mandatory peer-review and admin authorization.

### 2. System Administrator Impersonation
Administrative oversight often requires viewing the system exactly as a specific user sees it to debug access issues or investigate suspicious activity. Traditional systems often rely on dangerous practices like sharing passwords or generating temporary backdoor credentials. NexusGuard's **Impersonation** feature solves this securely:
- **Zero-Credential Exposure:** System Administrators can temporarily assume the identity (Context Swap) of another user purely via API-level token translation. The target user's actual credentials (passwords, OAuth tokens) are never exposed, accessed, or required.
- **Strictly Gated Access:** This capability is hard-coded strictly for users flagged as `isSystemAdmin` in the core database. Standard Owners and Managers within organizations cannot use this feature, preventing lateral privilege escalation.
- **Comprehensive Audit Trail:** When an Admin impersonates a user, the Context Swap is flagged. Any actions taken while impersonating are logged in the `activity_logs` with a dual-identity tag. This ensures complete non-repudiation and accountability; an administrator cannot hide behind an impersonated user's identity to perform malicious actions undetected.

---

## 📁 Project Structure

Below is a detailed structural overview of the NexusGuard project:

```text
MINI_PROJECT_0100/
│
├── architecture_and_rbac_overview and algorithm  # Detailed system architecture doc
├── project_requirements_and_acm.txt              # Initial requirements & ACM details
├── firestore.rules                               # Database security rules
├── firestore.indexes.json                        # Database composite indexes
├── firebase.json                                 # Firebase deployment config
├── .firebaserc                                   # Firebase project aliases
├── .gitignore                                    # Git ignore definitions
├── README.md                                     # This file
│
├── frontend/                                     # React JS User Interface
│   ├── index.html                                # HTML Entry Point
│   ├── package.json                              # Frontend dependencies
│   ├── vite.config.js                            # Vite bundler configuration
│   ├── eslint.config.js                          # Linter configuration
│   ├── .env.example                              # Frontend environment template
│   ├── src/                                      # React Source Code
│   │   ├── main.jsx                              # React Root
│   │   ├── App.jsx                               # Application Component & Routes
│   │   ├── index.css                             # Tailwind and Global CSS
│   │   └── firebase.js                           # Client-side Firebase initialization
│   └── public/                                   # Static Assets
│
└── backend/                                      # Express JS Server
    ├── server.js                                 # Main API Server & Routing
    ├── package.json                              # Backend dependencies
    ├── .env.example                              # Backend environment template
    └── serviceAccountKey.json                    # Firebase Admin SDK Credentials
```

---

## 🔌 API Endpoints Overview

The backend exposes secure REST endpoints. All endpoints (except health) require a valid Firebase Auth JWT Bearer token.

| Method | Endpoint | Description | Access Required |
|--------|----------|-------------|-----------------|
| GET | `/api/health` | System health check | Authenticated |
| GET | `/api/user/activity` | Get user's audit logs | Authenticated |
| GET | `/api/user/organizations`| List user's orgs | Authenticated |
| GET | `/api/resources` | List accessible resources | Org Member / Public |
| GET | `/api/resources/:id/detail`| Get resource & assigned users| Org Member |
| POST | `/api/resources` | Create a new resource | `WRITE` Privilege |
| PUT | `/api/resources/:id` | Update a resource | Admin/Owner or Granular `WRITE` |
| PUT | `/api/resources/:id/roles` | Update provision roles | Administrator or Editor |
| DELETE| `/api/resources/:id` | Delete a resource | Admin/Owner or Granular `WRITE` |

---

## 📜 Audit Logging System

Every mutating request is monitored by a custom Express middleware.
- **Logger Middleware:** Intercepts `POST`, `PUT`, and `DELETE` requests.
- **Anonymization:** Masks sensitive data (like passwords or verification codes) before logging.
- **Context Awareness:** Captures User ID, Name, Email, IP Address, Organization ID, and the specific action taken.
- **Immutability:** Logs are written to the `activity_logs` Firestore collection, which cannot be modified or deleted by standard users.

---

## ⚙️ Installation & Setup

### Prerequisites
- Node.js (v18+ recommended)
- Git
- Firebase Project with Firestore and Authentication enabled.

### 1. Clone the Repository
```bash
git clone <repository-url>
cd MINI_PROJECT_0100
```

### 2. Backend Setup
```bash
cd backend
npm install
```

### 3. Frontend Setup
```bash
cd ../frontend
npm install
```

---

## 🔐 Configuration (Environment Variables)

### Backend (`backend/.env`)
Create a `.env` file in the `backend` directory based on `backend/.env.example`.

```env
PORT=5000
CORS_ORIGIN=http://localhost:5173
FIREBASE_PROJECT_ID=your-project-id
# Optionally, paste your service account JSON here for production
# FIREBASE_SERVICE_ACCOUNT_JSON=
```

### Frontend (`frontend/.env`)
Create a `.env` file in the `frontend` directory based on `frontend/.env.example`.

```env
VITE_API_BASE_URL=http://localhost:5000/api
VITE_FIREBASE_API_KEY=your_api_key_here
VITE_FIREBASE_AUTH_DOMAIN=your_project_id.firebaseapp.com
VITE_FIREBASE_PROJECT_ID=your_project_id
VITE_FIREBASE_STORAGE_BUCKET=your_project_id.firebasestorage.app
VITE_FIREBASE_MESSAGING_SENDER_ID=your_sender_id
VITE_FIREBASE_APP_ID=your_app_id
```

---

## 🔥 Firebase Setup

1. Go to the [Firebase Console](https://console.firebase.google.com/).
2. Create a new project.
3. Enable **Authentication** (Email/Password & Google Sign-In).
4. Enable **Firestore Database**.
5. Deploy the security rules:
   ```bash
   firebase deploy --only firestore:rules
   ```
6. Generate a New Private Key for the Firebase Admin SDK:
   - Project Settings > Service Accounts > Generate new private key.
   - Save the file as `backend/serviceAccountKey.json`.

---

## 🚀 Running the Application

### Start the Backend Server
```bash
cd backend
npm run dev
# Server will start on port 5000
```

### Start the Frontend Client
```bash
cd frontend
npm run dev
# Vite will start on port 5173
```

Navigate to `http://localhost:5173` in your browser.

---

## 🖥 Hardware Requirements

- **Client:** Any device capable of running a modern web browser (Chrome, Firefox, Safari, Edge) with at least 2GB RAM.
- **Production Server:** Minimum 1 vCPU, 1GB RAM, 1GB+ Storage.
- **Development Environment:** Multi-core processor, minimum 4GB RAM (8GB+ recommended).

---

## 🤝 Contributing

Contributions to NexusGuard are welcome!
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/AmazingFeature`).
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

Ensure all code follows the existing ESLint configurations and passes any access control tests.

---

## 📄 License

This project is licensed under the ISC License.
