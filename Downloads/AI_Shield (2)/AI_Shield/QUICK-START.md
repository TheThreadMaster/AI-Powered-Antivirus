# 🚀 AI Shield - Quick Start Guide

**Simple step-by-step guide to get AI Shield running in minutes!**

---

## 📋 Before You Start

Make sure you have these installed on your computer:
- ✅ **Python 3.8 or higher** - [Download here](https://www.python.org/downloads/)
- ✅ **Node.js 18 or higher** - [Download here](https://nodejs.org/)

> 💡 **Tip:** During Python installation on Windows, check the box that says "Add Python to PATH"

---

## 🎯 Step-by-Step Instructions

### PART 1: Setting Up the Backend (Python Server)

#### Step 1: Open Terminal/Command Prompt

**Windows:**
- Press `Windows Key + X` and select "Windows PowerShell" or "Terminal"
- OR press `Windows Key + R`, type `cmd`, and press Enter

**Mac/Linux:**
- Open Terminal (usually in Applications > Utilities)

#### Step 2: Navigate to the Backend Folder

Type this command (change the path to match where your project is located):

```bash
cd "C:\Users\arnot\Downloads\AI_Shield (2)\AI_Shield\backend"
```

> 💡 **Tip:** You can also navigate by typing `cd ` (with a space), then drag the backend folder into the terminal and press Enter.

#### Step 3: Create a Virtual Environment

**Windows:**
```powershell
python -m venv venv
```

**Mac/Linux:**
```bash
python3 -m venv venv
```

Wait a few seconds for it to complete. You won't see much output - that's normal!

#### Step 4: Activate the Virtual Environment

**Windows PowerShell:**
```powershell
venv\Scripts\Activate.ps1
```

> ⚠️ **If you see an error:** Type this first, then try again:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

**Windows Command Prompt (CMD):**
```cmd
venv\Scripts\activate.bat
```

**Mac/Linux:**
```bash
source venv/bin/activate
```

✅ **Success:** You'll see `(venv)` at the start of your command line, like this:
```
(venv) PS C:\Users\...\backend>
```

#### Step 5: Upgrade pip

```bash
python -m pip install --upgrade pip
```

Wait for it to finish (usually takes 10-30 seconds).

#### Step 6: Install Backend Dependencies

```bash
pip install -r requirements.txt
```

⏳ **This will take 2-5 minutes.** You'll see lots of text scrolling - that's normal! It's installing all the required packages.

✅ **Success:** You'll see something like "Successfully installed..." at the end.

---

### PART 2: Setting Up the Frontend (Web Interface)

#### Step 7: Open a NEW Terminal Window

> 💡 **Important:** Keep the first terminal open (with backend running). Open a completely new terminal window.

#### Step 8: Navigate to the Frontend Folder

```bash
cd "C:\Users\arnot\Downloads\AI_Shield (2)\AI_Shield\frontend"
```

#### Step 9: Install Frontend Dependencies

```bash
npm install
```

⏳ **This will take 2-3 minutes.** Wait for it to finish.

✅ **Success:** You'll see "added X packages" at the end.

---

### PART 3: Running the Application

#### Step 10: Start the Backend Server

**Go back to your FIRST terminal** (the one with `(venv)` shown).

Make sure you're in the backend folder and the virtual environment is activated, then type:

```bash
python run.py
```

✅ **Success:** You'll see messages like:
```
INFO:     Uvicorn running on http://127.0.0.1:8001
INFO:     Application startup complete.
```

🎉 **Leave this terminal open!** Don't close it.

#### Step 11: Start the Frontend Server

**Go to your SECOND terminal** (the frontend one).

Make sure you're in the frontend folder, then type:

```bash
npm run dev
```

✅ **Success:** You'll see:
```
▲ Next.js 16.0.3
- Local:        http://localhost:3000
```

🎉 **Leave this terminal open too!**

#### Step 12: Open the Dashboard

1. Open your web browser (Chrome, Firefox, Edge, Safari - any browser works)
2. Type this in the address bar: `http://localhost:3000`
3. Press Enter

🎊 **Congratulations!** The AI Shield dashboard should now be visible!

---

## ✅ Checklist - What Should Be Running

You should have:
- ✅ Terminal 1: Backend server running (showing "Uvicorn running...")
- ✅ Terminal 2: Frontend server running (showing "Next.js...")
- ✅ Browser: Dashboard open at `http://localhost:3000`

---

## 🛑 How to Stop the Application

To stop the servers:
1. Go to each terminal window
2. Press `Ctrl + C` (or `Cmd + C` on Mac)
3. Repeat for both terminals

---

## ❓ Troubleshooting

### Problem: "python is not recognized" or "python: command not found"

**Solution:**
- **Windows:** Reinstall Python and make sure to check "Add Python to PATH"
- **Mac/Linux:** Try using `python3` instead of `python`

### Problem: "npm is not recognized" or "npm: command not found"

**Solution:** Install Node.js from [nodejs.org](https://nodejs.org/) and restart your terminal.

### Problem: Backend won't start / Port already in use

**Solution:** Something else is using port 8001. Close other applications or restart your computer.

### Problem: Frontend won't start / Port 3000 already in use

**Solution:** Close any other web development servers you might have running.

### Problem: Installation takes too long or gets stuck

**Solution:** This is normal! Some packages take a while to install. Be patient, or check your internet connection.

### Problem: Virtual environment activation fails (Windows PowerShell)

**Solution:** Run this command first:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
Then try activating again.

---

## 📝 Quick Reference Card

**Starting Backend:**
```bash
cd backend
venv\Scripts\Activate.ps1          # Windows PowerShell
# OR
venv\Scripts\activate.bat          # Windows CMD
# OR
source venv/bin/activate           # Mac/Linux
python run.py
```

**Starting Frontend:**
```bash
cd frontend
npm run dev
```

**Access Dashboard:**
- Open browser: `http://localhost:3000`

---

## 🎓 Next Steps

Once everything is running:
1. Explore the dashboard tabs
2. Try uploading a file in "Manual Scanner"
3. Check out the "Metrics & Comparison" tab
4. View threats in the "Threat Feed"

---

## 💡 Tips

- **First time setup:** Takes about 5-10 minutes total
- **After first setup:** Starting takes only 10 seconds!
- **Keep terminals open:** Both servers need to keep running
- **Restart if needed:** If something goes wrong, just restart both servers

---

## 📞 Still Having Issues?

1. Make sure Python 3.8+ and Node.js 18+ are installed
2. Verify you followed all steps in order
3. Check that both terminals show the correct folder paths
4. Ensure no other programs are using ports 8001 or 3000

For detailed troubleshooting, see `INSTALL.md` or `backend/README-INSTALL.md`

---

**Happy Protecting! 🛡️**

