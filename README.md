# CTI Platform

Cyber Threat Intelligence analysis and orchestration platform bridging Python analytics with PowerShell v3.1 endpoint triage.

## Features

- **FastAPI Backend** — Async Python API with structured logging, request tracing, and hardened security headers
- **Threat Intelligence Management** — IOC ingestion, feed parsing, and indicator correlation
- **Malware Analysis Engine** — Pluggable analysis modules (adware, trojan, etc.) with Celery task queue support
- **PowerShell Bridge** — REST API integration with the v3.1 Triage Toolbox via Base64-encoded JSON triggers
- **React Frontend** — Modern Vite-based dashboard for analysts

## Architecture

```
cti_platform
├── backend/           # FastAPI application
│   ├── api/v1/        # REST API routes
│   ├── core/          # Security, config, utilities
│   ├── integrations/  # External threat feed collectors
│   └── analysis_engine/  # Malware analysis modules
├── frontend/          # React application
├── data/              # Local database & raw feeds
├── scripts/           # Utility & test scripts
└── docker/            # Container definitions
```

## Quick Start

### Prerequisites

- Python 3.12+
- Node.js 20+ (for frontend)
- Redis (optional, for Celery task queues)

### Backend Setup

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/cti_platform.git
cd cti_platform

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Initialize database
python scripts/init_db.py

# Run server
python -m backend.main
# or
uvicorn backend.main:app --reload
```

The API will be available at `http://localhost:8000` with interactive docs at `/docs`.

### Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

## PowerShell Bridge Integration

The platform communicates with the v3.1 Triage Toolbox via the `POWERSHELL_BRIDGE_URL`. Configure the bridge URL and shared secret in your `.env` file. Ensure the PowerShell scripts respect `$Global:UI_MODE` to prevent terminal hangs during automated execution.

## Configuration

All configuration is managed via environment variables or a `.env` file. Key settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `DEBUG` | Enable debug mode | `False` |
| `DATABASE_URL` | Database connection string | `sqlite:///./data/cti.db` |
| `SECRET_KEY` | JWT signing key | Auto-generated |
| `BACKEND_CORS_ORIGINS` | Allowed frontend origins | `http://localhost:3000` |
| `POWERSHELL_BRIDGE_URL` | PowerShell bridge endpoint | — |

See `.env.example` for the full configuration reference.

## Development

### Running Tests

```bash
pytest backend/tests/ -v
```

### Code Style

```bash
black backend/
ruff check backend/
```

## Security Notes

- Never commit `.env` files or API keys to version control
- Change `SECRET_KEY` immediately for production deployments
- Use `ALLOWED_HOSTS` to restrict incoming Host headers (production)
- Review `Content-Security-Policy` headers if serving frontend from the same domain

## License

[MIT](LICENSE)
