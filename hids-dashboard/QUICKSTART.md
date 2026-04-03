# 🚀 HIDS Dashboard - Quick Start Guide

## Prerequisites
- Node.js 18+
- Python 3.8+
- MongoDB running (localhost:27017)

## Installation (One Command)
```bash
npm run install:all
```

## Run Application (One Command)
```bash
npm run dev
```

## Access Points
- **Frontend:** http://localhost:5173
- **Express API:** http://localhost:5000
- **Flask API:** http://localhost:5001

## First Login
1. Go to http://localhost:5173
2. Click "Register here"
3. Create account (any email format works)
4. Explore the dashboard!

## Default Data
The app comes with 28 sample requests showing:
- 10 normal requests
- 7 SQL injection attacks
- 5 XSS attacks
- 3 path traversal attacks
- 3 command injection attacks

## Common Issues

### MongoDB Connection Failed
**Solution:** Ensure MongoDB is running
```bash
# macOS/Linux
mongod

# Windows
net start MongoDB
```

### Port Already in Use
**Solution:** Kill processes on ports 5000, 5001, or 5173
```bash
# macOS/Linux
lsof -ti:5000 | xargs kill
lsof -ti:5001 | xargs kill
lsof -ti:5173 | xargs kill

# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Python Dependencies Error
**Solution:** Install Flask dependencies manually
```bash
pip install -r flask_api/requirements.txt
```

### React Build Error
**Solution:** Reinstall client dependencies
```bash
cd client
rm -rf node_modules
npm install
```

## Individual Commands

### Install Dependencies
```bash
# Root dependencies
npm install

# Client dependencies
cd client && npm install

# Python dependencies
pip install -r flask_api/requirements.txt
```

### Run Servers Individually
```bash
# Terminal 1: Express Server
npm run server

# Terminal 2: Flask API
npm run flask

# Terminal 3: React Client
npm run client
```

### Build for Production
```bash
cd client
npm run build
```

## Project Structure Overview
```
hids-dashboard/
├── server/         # Express (Auth + Data APIs)
├── flask_api/      # Flask (Upload + Processing)
├── client/         # React (UI)
└── output/         # Sample data files
```

## Key Features to Test

✅ **Authentication**
- Register → Login → Logout

✅ **Dashboard**
- View statistics
- See pie chart of attacks
- Check timeline graph

✅ **Requests**
- Search by IP or URL
- Filter by attack type
- Click row for details

✅ **Analysis**
- View IP risk levels
- Feature importance chart
- Detection method breakdown

✅ **Upload**
- Upload log/pcap/csv file
- Run analysis
- View processing progress

## API Testing (Optional)

### Test Authentication
```bash
# Register
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@example.com","password":"test123"}'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"test123"}'
```

### Test Data APIs (requires token)
```bash
# Get summary
curl http://localhost:5000/api/summary \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"

# Get requests
curl http://localhost:5000/api/requests \
  -H "Authorization: Bearer YOUR_TOKEN_HERE"
```

## Troubleshooting Tips

1. **Clear browser cache** if seeing old data
2. **Check browser console** for React errors
3. **Check terminal logs** for server errors
4. **Verify MongoDB is running** before starting servers
5. **Ensure all ports are free** before running dev

## Support

For issues or questions:
1. Check the main README.md
2. Verify all dependencies are installed
3. Ensure MongoDB is running
4. Check that all three servers started successfully

---

**Happy Testing! 🎉**
