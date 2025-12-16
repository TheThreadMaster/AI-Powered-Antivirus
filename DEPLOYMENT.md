# Deployment Guide

This guide covers deploying AI-Powered Antivirus on various platforms.

## Architecture Overview

- **Frontend**: Next.js 16 (deploy on Vercel or Netlify)
- **Backend**: FastAPI (deploy on Render, Railway, or Fly.io)

## Option 1: Vercel (Frontend) + Render (Backend) - Recommended

### Frontend Deployment on Vercel

1. **Connect Repository to Vercel**
   - Go to [vercel.com](https://vercel.com)
   - Sign in with GitHub
   - Click "New Project"
   - Import your repository: `TheThreadMaster/AI-Powered-Antivirus`

2. **Configure Project Settings**
   - **Root Directory**: `frontend`
   - **Framework Preset**: Next.js
   - **Build Command**: `npm run build` (default)
   - **Output Directory**: `.next` (default)
   - **Install Command**: `npm install`

3. **Environment Variables**
   Add these in Vercel dashboard → Settings → Environment Variables:
   ```
   NEXT_PUBLIC_API_BASE=https://your-backend.onrender.com
   NEXT_PUBLIC_WS_URL=wss://your-backend.onrender.com/ws
   ```

4. **Deploy**
   - Click "Deploy"
   - Vercel will automatically build and deploy your frontend

### Backend Deployment on Render

1. **Create New Web Service**
   - Go to [render.com](https://render.com)
   - Sign in with GitHub
   - Click "New +" → "Web Service"
   - Connect your repository

2. **Configure Service**
   - **Name**: `ai-powered-antivirus-backend`
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Root Directory**: `backend` (or leave blank if backend is at root)

3. **Environment Variables**
   Add in Render dashboard → Environment:
   ```
   FRONTEND_ORIGIN=https://your-frontend.vercel.app
   PORT=10000
   ```

4. **Database (Optional)**
   - If using SQLite, it will be ephemeral (resets on restart)
   - For production, add a PostgreSQL database:
     - Click "New +" → "PostgreSQL"
     - Update `backend/app/store.py` to use PostgreSQL connection string

5. **Deploy**
   - Click "Create Web Service"
   - Render will build and deploy your backend

### Update Frontend Environment Variables

After backend is deployed, update Vercel environment variables with your Render backend URL.

---

## Option 2: Netlify (Frontend) + Render (Backend)

### Frontend Deployment on Netlify

1. **Connect Repository**
   - Go to [netlify.com](https://netlify.com)
   - Sign in with GitHub
   - Click "Add new site" → "Import an existing project"
   - Select your repository

2. **Build Settings**
   - **Base directory**: `frontend`
   - **Build command**: `npm run build`
   - **Publish directory**: `frontend/.next`

3. **Environment Variables**
   Add in Site settings → Environment variables:
   ```
   NEXT_PUBLIC_API_BASE=https://your-backend.onrender.com
   NEXT_PUBLIC_WS_URL=wss://your-backend.onrender.com/ws
   ```

4. **Deploy**
   - Click "Deploy site"

### Backend Deployment
Follow the same Render backend deployment steps from Option 1.

---

## Option 3: Railway (Full Stack)

Railway can deploy both frontend and backend.

### Deploy Backend

1. **Create New Project**
   - Go to [railway.app](https://railway.app)
   - Sign in with GitHub
   - Click "New Project" → "Deploy from GitHub repo"

2. **Configure Backend Service**
   - Select your repository
   - Railway will auto-detect Python
   - Set **Start Command**: `cd backend && uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Add environment variable: `FRONTEND_ORIGIN=https://your-frontend.vercel.app`

### Deploy Frontend

1. **Add Frontend Service**
   - In the same Railway project, click "+ New" → "GitHub Repo"
   - Select the same repository
   - Set **Root Directory**: `frontend`
   - Set **Build Command**: `npm install && npm run build`
   - Set **Start Command**: `npm start`
   - Add environment variables:
     ```
     NEXT_PUBLIC_API_BASE=https://your-backend.railway.app
     NEXT_PUBLIC_WS_URL=wss://your-backend.railway.app/ws
     ```

---

## Environment Variables Reference

### Frontend (Next.js)
```bash
NEXT_PUBLIC_API_BASE=https://your-backend-url.com
NEXT_PUBLIC_WS_URL=wss://your-backend-url.com/ws
```

### Backend (FastAPI)
```bash
FRONTEND_ORIGIN=https://your-frontend-url.com
PORT=10000  # Render uses $PORT, Railway uses PORT
```

---

## Important Notes

### WebSocket Support
- **Vercel**: WebSockets require Vercel Pro plan or use Serverless Functions
- **Netlify**: Limited WebSocket support, consider using polling
- **Render**: Full WebSocket support on free tier
- **Railway**: Full WebSocket support

### Database Considerations
- SQLite files are ephemeral on most platforms
- For production, use PostgreSQL:
  - Render: Add PostgreSQL database service
  - Railway: Add PostgreSQL service
  - Update connection string in `backend/app/store.py`

### CORS Configuration
Ensure your backend allows your frontend origin:
```python
# In backend/app/main.py
app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("FRONTEND_ORIGIN", "http://localhost:3000")],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### File Upload Limits
- Vercel: 4.5MB limit (free tier)
- Netlify: 6MB limit
- Render: No specific limit, but consider file size
- Railway: No specific limit

---

## Troubleshooting

### Backend Not Starting
- Check logs in your platform's dashboard
- Verify `PORT` environment variable is set correctly
- Ensure all dependencies are in `requirements.txt`

### Frontend Can't Connect to Backend
- Verify `NEXT_PUBLIC_API_BASE` is set correctly
- Check CORS settings in backend
- Ensure backend URL is accessible (not localhost)

### WebSocket Connection Issues
- Verify `NEXT_PUBLIC_WS_URL` uses `wss://` (secure WebSocket)
- Check if your platform supports WebSockets
- Consider implementing fallback polling for Netlify

---

## Recommended Setup

**For Best Performance:**
- Frontend: Vercel (excellent Next.js support)
- Backend: Render (good free tier, WebSocket support)

**For Simplicity:**
- Both on Railway (single platform, easier management)

**For Cost:**
- Frontend: Vercel (free tier is generous)
- Backend: Render (free tier available, spins down after inactivity)

---

## Next Steps After Deployment

1. Update your README with live deployment URLs
2. Set up custom domains (optional)
3. Configure SSL certificates (usually automatic)
4. Set up monitoring and alerts
5. Configure database backups (if using PostgreSQL)

