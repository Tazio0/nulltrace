# ThreatWatch

ThreatWatch is a cybersecurity-focused threat intelligence dashboard built with Python, FastAPI, PostgreSQL, Docker, and Pytest.

It collects and processes threat intelligence from public security feeds, helping surface suspicious IPs, malicious URLs, and security context in a structured backend system.

This is an educational portfolio project built to strengthen my backend development, API design, testing, Docker, database, and cybersecurity skills.

## Current Status

ThreatWatch is actively being developed.

Working:
- Backend API structure
- Threat feed ingestion foundation
- Database integration
- Environment-based configuration
- Test suite
- Docker Compose setup

In progress:
- Dashboard/frontend
- More threat intelligence sources
- Improved South African threat context
- Better scoring and filtering logic

## Why I Built This

I built ThreatWatch because I wanted a portfolio project that connects backend development with cybersecurity.

Instead of building another basic CRUD app, I wanted to work on something closer to real-world security tooling: collecting external threat data, processing it safely, storing it properly, testing the logic, and presenting the information in a useful way.

The goal of this project is to show that I can build structured backend systems, work with APIs, write tests, use Docker, and think about security-focused software responsibly.

## What This Project Shows

This project demonstrates my ability to:

- Design and structure a backend application
- Build APIs with FastAPI
- Work with PostgreSQL and SQLAlchemy
- Use Docker Compose for local development
- Write and run tests with Pytest
- Handle configuration through environment variables
- Work with external API data
- Document a project clearly
- Think about security tools responsibly

## Running Tests

From the project root:

```bash
PYTHONPATH=. python -m pytest

Discord alert output
<img width="431" height="777" alt="image" src="https://github.com/user-attachments/assets/6e354586-6be9-4f8c-8aff-4641e11de54f" />

## Roadmap

- [x] Set up FastAPI backend
- [x] Add PostgreSQL database support
- [x] Add Docker Compose development environment
- [x] Add Pytest test suite
- [ ] Improve threat scoring logic
- [ ] Add dashboard interface
- [ ] Add authentication
- [ ] Add deployment instructions
- [ ] Add CI pipeline with GitHub Actions
- [ ] Deploy demo version
