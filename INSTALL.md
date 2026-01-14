# AI Shield - Complete Installation Guide

This guide provides step-by-step instructions for installing AI Shield on **Windows, Linux, and macOS**.

## Prerequisites Check

Before starting, verify you have the required software:

```bash
# Check Python version (need 3.8 or higher)
python --version
# OR on some systems:
python3 --version

# Check Node.js version (need 18 or higher)
node --version

# Check npm version
npm --version
```

If any are missing:
- **Python:** Download from [python.org](https://www.python.org/downloads/)
- **Node.js:** Download from [nodejs.org](https://nodejs.org/)

---

## Quick Start (All Platforms)

### Backend Installation

**1. Open terminal/command prompt and navigate to project:**
```bash
cd "path/to/AI_Shield/backend"
```

**2. Create and activate virtual environment:**

*Windows PowerShell:*
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

*Windows CMD:*
```cmd
python -m venv venv
venv\Scripts\activate.bat
```

*Linux/macOS:*
```bash
python3 -m venv venv
source venv/bin/activate
```

**3. Install dependencies:**
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Frontend Installation

**1. Open a NEW terminal and navigate to frontend:**
```bash
cd "path/to/AI_Shield/frontend"
```

**2. Install dependencies:**
```bash
npm install
```

---

## Running the Application

### Terminal 1 - Backend Server

**Activate virtual environment** (if not already active), then:

*Windows PowerShell:*
```powershell
cd backend
venv\Scripts\Activate.ps1
python run.py
```

*Windows CMD:*
```cmd
cd backend
venv\Scripts\activate.bat
python run.py
```

*Linux/macOS:*
```bash
cd backend
source venv/bin/activate
python run.py
```

✅ Backend running at: `http://127.0.0.1:8001`

### Terminal 2 - Frontend Server

```bash
cd frontend
npm run dev
```

✅ Frontend running at: `http://localhost:3000`

### Open Browser

Navigate to: **`http://localhost:3000`**

---

## Troubleshooting

### Python Command Not Found

**Problem:** `python` command doesn't work

**Solution:**
- **Windows:** Reinstall Python and check "Add Python to PATH" during installation
- **Linux/macOS:** Use `python3` instead of `python`

### Virtual Environment Activation Fails (Windows PowerShell)

**Problem:** `Activate.ps1` shows execution policy error

**Solution:**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then try activation again.

### pip Install Fails

**Problem:** Installation errors or permission denied

**Solution 1 (Recommended):** Use virtual environment (see steps above)

**Solution 2:** Install for current user only:
```bash
pip install --user -r requirements.txt
```

**Solution 3:** Upgrade pip first:
```bash
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

### orjson Installation Fails

**Problem:** Error installing orjson package

**Solution:** This is **optional**. The app will work without it (uses built-in JSON). You can continue installation - the app will function normally.

### npm Install Fails

**Problem:** npm errors or slow installation

**Solution 1:** Clear npm cache:
```bash
npm cache clean --force
npm install
```

**Solution 2:** Use yarn instead:
```bash
yarn install
```

### Port Already in Use

**Problem:** Port 8001 or 3000 already in use

**Solution:** 
- **Backend:** Change port in `backend/run.py` or set environment variable: `PORT=8002`
- **Frontend:** Kill the process using the port or change port in `frontend/package.json`

---

## Platform-Specific Notes

### Windows

- Use PowerShell or CMD - both work fine
- If you see "python is not recognized", reinstall Python with "Add to PATH" option
- Visual C++ Build Tools may be needed for some packages (usually auto-installed)

### Linux

- You may need: `sudo apt-get install python3-dev python3-pip` (Ubuntu/Debian)
- Or: `sudo yum install python3-devel python3-pip` (CentOS/RHEL)
- Use `python3` instead of `python` if needed

### macOS

- Install Xcode Command Line Tools: `xcode-select --install`
- Use `python3` if `python` doesn't work
- Apple Silicon (M1/M2) works without additional configuration

---

## Verification

After installation, verify everything works:

**Backend:**
```bash
cd backend
venv\Scripts\Activate.ps1  # Windows PowerShell
# OR
source venv/bin/activate   # Linux/macOS
python -c "import fastapi, sqlmodel, uvicorn; print('✅ Backend ready!')"
```

**Frontend:**
```bash
cd frontend
npm list next react  # Should show versions
```

---

## Need Help?

1. Make sure Python 3.8+ and Node.js 18+ are installed
2. Ensure virtual environment is activated before installing backend dependencies
3. Check that both servers are running (backend on 8001, frontend on 3000)
4. Verify firewall isn't blocking the ports

For more details, see `backend/README-INSTALL.md`

