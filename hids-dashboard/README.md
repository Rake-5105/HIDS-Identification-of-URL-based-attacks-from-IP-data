# 🛡️ HIDS Dashboard

A production-grade, full-stack Host Intrusion Detection System (HIDS) Dashboard for visualizing URL-based attack detection results from a Python ML pipeline.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Browser (React)                    │
│         Vite + Tailwind + Recharts + Axios          │
└──────────────┬──────────────────┬───────────────────┘
               │ :5000            │ :5001
    ┌──────────▼──────┐   ┌───────▼────────────┐
    │  Express (Node) │   │   Flask (Python)    │
    │  Auth + Data    │   │  Upload + Pipeline  │
    └──────────┬──────┘   └───────┬────────────┘
               │                  │
    ┌──────────▼──────┐   ┌───────▼────────────┐
    │    MongoDB       │   │  Python ML Modules │
    │  (Users/Auth)    │   │  + /output/ files  │
    └─────────────────┘   └────────────────────┘
```

## ✨ Features

- **JWT Authentication** - Secure user registration and login
- **Real-time Dashboard** - Live threat statistics and visualizations
- **Request Analysis** - Detailed view of all URL requests with filtering and sorting
- **IP Risk Analysis** - Track suspicious IPs and threat percentages
- **File Upload** - Support for log files, PCAP files, and CSV data
- **ML Pipeline Integration** - Automatic processing through detection modules
- **Interactive Charts** - Recharts-based visualizations for attack distribution and timelines
- **Responsive Design** - Tailwind CSS with mobile-first approach

## 🚀 Quick Start

### Prerequisites

- Node.js (v18+)
- Python (v3.8+)
- MongoDB (local or remote instance)

### Installation

1. **Clone and navigate to the project**

```bash
cd hids-dashboard
```

2. **Install all dependencies**

```bash
npm run install:all
```

This will install:
- Root Node.js dependencies
- Client (React) dependencies
- Python Flask dependencies

### Configuration

1. **Environment Variables**

The `.env` file is already configured with defaults:

```env
MONGODB_URI=mongodb://localhost:27017/hids_dashboard
JWT_SECRET=hids_super_secret_jwt_key_change_in_production
PORT=5000
FLASK_PORT=5001
NODE_ENV=development
```

**⚠️ Important:** Change `JWT_SECRET` in production!

2. **MongoDB Setup**

Ensure MongoDB is running:

```bash
# macOS/Linux
mongod

# Windows
net start MongoDB
```

### Running the Application

**Start all services concurrently:**

```bash
npm run dev
```

This will start:
- **Express Server** on http://localhost:5000
- **Flask API** on http://localhost:5001
- **React Client** on http://localhost:5173

### First Time Setup

1. Open http://localhost:5173
2. Click "Register here"
3. Create an account with:
   - Username
   - Email
   - Password (min 6 characters)
4. Login and explore the dashboard!

## 📁 Project Structure

```
hids-dashboard/
├── server/                  # Express Backend (Node.js)
│   ├── config/             # MongoDB connection
│   ├── models/             # User model
│   ├── middleware/         # JWT authentication
│   ├── routes/             # API routes
│   └── utils/              # Data loaders
│
├── flask_api/              # Flask Backend (Python)
│   ├── routes/             # Upload & processing routes
│   ├── services/           # File processors
│   └── uploads/            # Temporary upload storage
│
├── client/                 # React Frontend (Vite)
│   └── src/
│       ├── components/     # Reusable UI components
│       ├── pages/          # Page components
│       ├── context/        # Authentication context
│       └── hooks/          # Custom React hooks
│
└── output/                 # ML pipeline output files
    ├── module4_summary.json
    ├── module4_hybrid_results.csv
    └── url_feature_dataset.csv
```

## 🔌 API Endpoints

### Authentication (Public)
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/me` - Get current user (protected)

### Data APIs (Protected)
- `GET /api/summary` - Dashboard summary statistics
- `GET /api/requests` - All detection requests
- `GET /api/requests/:index` - Single request details
- `GET /api/analysis/ips` - IP risk analysis
- `GET /api/analysis/timeline` - Threat timeline data
- `GET /api/analysis/features` - Feature importance data
- `GET /api/analysis/methods` - Detection method breakdown

### Upload & Processing
- `POST /api/upload/logs` - Upload log files (.log, .txt)
- `POST /api/upload/pcap` - Upload PCAP files (.pcap, .pcapng)
- `POST /api/upload/csv` - Upload CSV files (.csv)
- `POST /api/process/:upload_id` - Start ML pipeline
- `GET /api/process/status/:upload_id` - Check processing status

## 🎨 UI Components

### Dashboard
- **Stat Cards** - Total requests, threats, ML accuracy, suspicious IPs
- **Attack Pie Chart** - Distribution by attack type
- **Timeline Chart** - Threats over time
- **Recent Threats** - Latest 10 threat detections
- **Suspicious IPs** - Alert list with navigation

### Requests Page
- **Search & Filter** - By IP or URL, filter by classification
- **Sortable Table** - Click headers to sort by any column
- **Color-coded Badges** - Visual classification indicators
- **Confidence Progress Bars** - Visual confidence levels
- **Detail Panel** - Slide-over with full request information

### Analysis Page
- **IP Risk Table** - Risk levels: Critical, High, Medium, Low
- **Feature Importance Chart** - Top 10 ML features
- **Detection Method Breakdown** - Pie chart for Regex/ML/Statistical

### Upload Page
- **Tabbed Interface** - Separate tabs for Log/PCAP/CSV
- **Drag & Drop** - File upload with progress tracking
- **Pipeline Progress** - Step-by-step processing visualization
- **Results Summary** - Display processing results

## 🔒 Security Features

- **Password Hashing** - bcryptjs with 10 salt rounds
- **JWT Tokens** - 7-day expiry, secure HTTP-only recommended for production
- **Protected Routes** - Middleware authentication on all data endpoints
- **Auto-logout** - Automatic redirect on 401 responses
- **File Validation** - Extension and MIME type checking
- **File Size Limits** - 50MB maximum upload size
- **XSS Protection** - React's built-in escaping
- **CORS Configuration** - Restricted to localhost in development

## 🎯 Attack Type Classification

The system detects and classifies the following attack types:

| Attack Type | Color | Description |
|------------|-------|-------------|
| **Normal** | Green | Legitimate traffic |
| **SQL Injection (SQLi)** | Red | Database manipulation attempts |
| **Cross-Site Scripting (XSS)** | Orange | Script injection attempts |
| **Path Traversal** | Yellow | Directory traversal attempts |
| **Command Injection (CMDi)** | Purple | OS command injection attempts |

## 🧪 Testing

### Sample Data
The project includes sample data in `output/` directory:
- 28 sample requests
- 18 threats across multiple attack types
- 96.4% ML accuracy
- 3 suspicious IPs

### Manual Testing Checklist

**Authentication:**
- [ ] Register with valid credentials
- [ ] Login with correct password
- [ ] Login fails with wrong password
- [ ] Logout clears session
- [ ] Protected routes redirect to login when not authenticated

**Dashboard:**
- [ ] Stat cards display correct numbers
- [ ] Pie chart renders with color-coded segments
- [ ] Timeline shows threat progression
- [ ] Recent threats list displays
- [ ] Suspicious IPs are clickable

**Requests:**
- [ ] Table displays all 28 requests
- [ ] Search filters by IP and URL
- [ ] Dropdown filters by classification
- [ ] Column sorting works (asc/desc)
- [ ] Row click opens detail panel
- [ ] Confidence bars render correctly

**Analysis:**
- [ ] IP risk table shows threat percentages
- [ ] Risk levels color-coded correctly
- [ ] Feature importance chart renders
- [ ] Detection method pie chart displays

**Upload:**
- [ ] File type tabs switch correctly
- [ ] Drag & drop accepts files
- [ ] Upload shows progress bar
- [ ] Run Analysis triggers pipeline
- [ ] Progress steps animate
- [ ] Results display on completion

## 🚢 Production Deployment

### Environment Variables for Production

```env
MONGODB_URI=mongodb://your-production-db:27017/hids
JWT_SECRET=your-super-secure-random-string-here
PORT=5000
FLASK_PORT=5001
NODE_ENV=production
```

### Build for Production

```bash
# Build React frontend
cd client
npm run build

# The build output will be in client/dist/
```

### Deployment Checklist

- [ ] Change JWT_SECRET to a strong random string
- [ ] Set up production MongoDB instance (MongoDB Atlas recommended)
- [ ] Configure CORS for production domain
- [ ] Enable HTTPS/TLS
- [ ] Set secure, httpOnly cookies for JWT
- [ ] Configure rate limiting
- [ ] Set up logging and monitoring
- [ ] Configure file upload size limits
- [ ] Set up backup strategy for MongoDB
- [ ] Configure environment-specific variables

## 🛠️ Development Scripts

```bash
# Install all dependencies
npm run install:all

# Start all services (Express + Flask + React)
npm run dev

# Start individual services
npm run server    # Express only
npm run client    # React only
npm run flask     # Flask only

# Build React for production
npm run build
```

## 📝 Known Limitations

1. **Processing Status** - Currently uses in-memory storage; use Redis in production
2. **File Storage** - Uploaded files stored locally; consider cloud storage (S3, GCS)
3. **ML Pipeline** - Services contain placeholder code; integrate actual Python modules
4. **Real-time Updates** - Uses polling; consider WebSockets for production
5. **Session Management** - Token stored in localStorage; consider secure httpOnly cookies

## 🤝 Contributing

This is a college mini-project. For modifications:

1. Follow the existing code structure
2. Maintain consistent naming conventions
3. Update this README if adding features
4. Test all authentication flows
5. Ensure responsive design works

## 📄 License

MIT License - This is an educational project.

## 🙏 Acknowledgments

- React + Vite for fast development
- Tailwind CSS for styling
- Recharts for beautiful visualizations
- MongoDB for flexible data storage
- Express.js for robust backend
- Flask for Python integration

---

**Built with ❤️ for HIDS Security Analysis**
