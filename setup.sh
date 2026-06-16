#!/bin/bash
set -e

echo "ThreatWatch — Environment Setup"
echo "===================================="
echo ""

if ! command -v python3 &> /dev/null; then
    echo "python3 not found. Install Python 3.11+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "✓ Found Python $PYTHON_VERSION"

if [ ! -d "venv" ]; then
    echo "→ Creating virtual environment..."
    python3 -m venv venv
else
    echo "✓ Virtual environment already exists"
fi

source venv/bin/activate
echo "✓ Virtual environment activated"

pip install --upgrade pip -q
echo "→ Installing dependencies from requirements.txt..."
pip install -r requirements.txt -q
echo "✓ Dependencies installed"

if [ ! -f ".env" ]; then
    if [ -f ".env.example" ]; then
        cp .env.example .env
        echo "✓ Created .env from .env.example — add your API keys before running"
    fi
else
    echo "✓ .env already exists"
fi

echo ""
echo "===================================="
echo "Setup complete."
echo ""
echo "Next steps:"
echo "  1. Add your API keys to .env"
echo "  2. Run: source venv/bin/activate"
echo "  3. Run: docker-compose up -d        (starts PostgreSQL)"
echo "  4. Run: pytest backend/tests/ -v    (confirms everything works)"
echo "===================================="
