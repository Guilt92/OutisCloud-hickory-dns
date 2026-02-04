# Hickory DNS Manager - Integration & Setup

## 🚀 Quick Start (30 seconds)

```bash
cd ./
bash integrate.sh
```

Then open http://localhost:3000 and login with `admin` / `admin123`

## 📋 What's Included

### Master Integration Script
- **integrate.sh** - Complete orchestration (PostgreSQL + API + UI + Tests)
- **run_quick_integration.sh** - Fast development mode
- **stop-services.sh** - Clean service shutdown
- **check_system.sh** - Prerequisite verification

### Complete System
- ✅ PostgreSQL 15 database
- ✅ Rust API backend (Actix-web)
- ✅ React UI frontend (Vite dev server)
- ✅ E2E test suite (40+ scenarios)
- ✅ Production readiness checks

## 🎯 Main Commands

```bash
# Full integration (RECOMMENDED)
bash integrate.sh

# Quick development mode
bash run_quick_integration.sh

# Stop all services
bash stop-services.sh

# Check if system is ready
bash check_system.sh

# View real-time logs
tail -f /tmp/hickory-logs/api.log
tail -f /tmp/hickory-logs/ui.log
```

## ✅ System Requirements

- **Docker** - PostgreSQL container
- **Node.js 16+** - UI development
- **Rust** - API backend
- **Ports:** 5432 (Postgres), 8080 (API), 3000 (UI)

## 📊 Service Architecture

```
integrate.sh (entry point)
    ↓
Docker PostgreSQL (port 5432)
    ↓
Rust API - Actix-web (port 8080)
    ↓
React UI - Vite dev server (port 3000)
    ↓
Optional: Playwright E2E Tests
```

## 🌐 Access Points

| Service | URL | Purpose |
|---------|-----|---------|
| UI | http://localhost:3000 | DNS Manager application |
| API | http://localhost:8080 | Backend REST API |
| Health | http://localhost:8080/health | API health check |
| Database | localhost:5432 | PostgreSQL database |

**Login Credentials:**
- Username: `admin`
- Password: `admin123`

## 📁 Project Structure

```
.//
├── integrate.sh                     ← Master script
├── run_quick_integration.sh         ← Quick mode
├── stop-services.sh                ← Stop services
├── check_system.sh                  ← System check
│
├── crates/
│   └── control_api/                 ← Rust backend
│       └── src/
├── web/
│   └── ui/                          ← React frontend
│       ├── src/
│       ├── tests/
│       └── package.json
├── tests/                           ← Integration tests
│
├── INTEGRATION.md                   ← Usage guide
├── SCRIPTS_CONSOLIDATED.md          ← Consolidation summary
└── INTEGRATION_TROUBLESHOOTING.md   ← Problem solving
```

## ⏱️ Timing

**First Run:** 10-15 minutes
- PostgreSQL: 15 sec
- API build: 3-5 min
- npm install: 1-2 min
- Services startup: 30 sec

**Subsequent Runs:** 1-2 minutes
- All cached, no rebuilds

## 📝 Documentation

| File | Purpose |
|------|---------|
| **INTEGRATION.md** | How to use scripts |
| **SCRIPTS_CONSOLIDATED.md** | What changed |
| **INTEGRATION_TROUBLESHOOTING.md** | Problem solving |
| **README.md** | Project overview |
| **DEVELOPER_QUICK_GUIDE.md** | Development guide |

## 🔍 Monitoring

View service logs in real-time:

```bash
# API logs
tail -f /tmp/hickory-logs/api.log

# UI logs
tail -f /tmp/hickory-logs/ui.log

# PostgreSQL logs
tail -f /tmp/hickory-logs/postgres.log

# Build logs
tail -f /tmp/hickory-logs/build.log
```

Check service status:

```bash
# All processes
ps aux | grep -E "(control_api|npm|postgres)" | grep -v grep

# PostgreSQL running?
docker ps | grep hickory-postgres

# Ports in use?
netstat -tulpn | grep -E "(3000|8080|5432)"
```

## 🐛 Troubleshooting

**Docker not running:**
```bash
sudo systemctl start docker  # Linux
# or open Docker Desktop (Mac/Windows)
```

**Port conflicts:**
```bash
# Find process on port
lsof -i :3000  # or :8080 or :5432

# Kill it
kill -9 <PID>
```

**Dependencies issues:**
```bash
# Clean and reinstall
cd web/ui
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

**Build failures:**
```bash
cd crates/control_api
cargo clean
cargo build --release
```

See **INTEGRATION_TROUBLESHOOTING.md** for more help.

## 🧪 Running Tests

After services start, run E2E tests:

```bash
cd ./web/ui
npm run test:e2e
```

Tests include:
- Authentication (login/logout)
- Dashboard pages
- CRUD operations
- Filtering and search
- Dark mode
- Error handling

## 🛠️ Manual Service Setup

If you prefer to start services individually:

### PostgreSQL
```bash
docker run -d --name hickory-postgres --network host \
  -e POSTGRES_DB=hickory \
  -e POSTGRES_PASSWORD=password \
  postgres:15-alpine
```

### API
```bash
cd .//crates/control_api
export DATABASE_URL="postgres://postgres:password@localhost:5432/hickory"
export JWT_SECRET="dev-secret-key"
cargo build --release
./target/release/control_api
```

### UI
```bash
cd ./web/ui
npm install
npm run dev
```

## 🎓 Learning Resources

- **Rust Backend:** See `/crates/control_api/README.md`
- **React Frontend:** See `/web/ui/SETUP.md`
- **Architecture:** See `ARCHITECTURE.md`
- **API Reference:** See `DEVELOPER_QUICK_GUIDE.md`

## 📊 Features Implemented

✅ User authentication (login/logout/JWT)
✅ Dashboard with stats
✅ DNS records management (CRUD)
✅ Zone management
✅ Advanced filtering and search
✅ Dark mode toggle
✅ Responsive design
✅ Error handling
✅ Loading states
✅ Real-time updates

## 🚀 Production Deployment

For production setup, see:
- `README-DEPLOY.md` - Deployment guide
- `DESIGN_AND_DEPLOY.md` - Design and deployment
- `PRODUCTION_CHECKLIST.md` - Pre-deployment verification

## ❓ Support

**Check these first:**
1. `bash check_system.sh` - Verify prerequisites
2. `INTEGRATION_TROUBLESHOOTING.md` - Common issues
3. `/tmp/hickory-logs/` - Service logs

**Common patterns:**
- API not responding → Check build.log, ensure cargo build completed
- UI not loading → Check npm-install.log, node modules installed
- Database error → Check postgres.log, port 5432 available

## 🎉 Success Indicators

After `bash integrate.sh` completes:

```
✓ Docker: Available and running
✓ Node.js: Installed (v18.x.x)
✓ Rust: Installed (cargo 1.x.x)
✓ PostgreSQL container started
✓ PostgreSQL is ready
✓ API built successfully
✓ API process started
✓ API is ready
✓ Dependencies installed
✓ UI process started
✓ UI is ready
✓ INTEGRATION COMPLETE

Services are running:
  ✓ API running on http://localhost:8080
  ✓ UI running on http://localhost:3000
  ✓ PostgreSQL running on localhost:5432

Access the application:
  URL: http://localhost:3000
  Username: admin
  Password: admin123
```

---

**Ready to start?** Run: `bash integrate.sh`

For detailed help, see [INTEGRATION.md](INTEGRATION.md)
