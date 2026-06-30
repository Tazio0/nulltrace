"""Tests database engine creation, session lifecycle, metadata registration, and get_db."""

import types
import pytest
from unittest.mock import patch, MagicMock, call

SQLITE_MEMORY_URL = "sqlite:///:memory:"

class TestEngine:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_engine_can_be_created(self):
        from sqlalchemy import create_engine

        engine = create_engine(SQLITE_MEMORY_URL)
        assert engine is not None

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_engine_is_not_none(self):
        from backend.app.database import engine

        assert engine is not None

class TestSessionLocal:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_session_can_be_opened_and_closed(self):
        from backend.app.database import SessionLocal

        session = SessionLocal()
        assert session is not None
        session.close()

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_session_is_scoped_to_factory(self):
        from backend.app.database import SessionLocal

        session_a = SessionLocal()
        session_b = SessionLocal()

        try:
            assert session_a is not session_b, (
                "SessionLocal() must return a new session instance per call"
            )
        finally:
            session_a.close()
            session_b.close()

class TestBase:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_base_has_metadata(self):
        from backend.app.database import Base

        assert hasattr(Base, "metadata"), "Base must have a metadata attribute"

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_tables_registered_after_model_import(self):
        from backend.app.database import Base

        import backend.app.models

        table_names = set(Base.metadata.tables.keys())

        expected_tables = {"threats", "honeypot_logs", "firewall_rules"}
        for table in expected_tables:
            assert table in table_names, (
                f"Expected table '{table}' to be registered in Base.metadata "
                f"after importing models. Found: {table_names}"
            )

class TestGetDb:

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_get_db_is_generator(self):
        from backend.app.database import get_db

        gen = get_db()
        assert isinstance(gen, types.GeneratorType), (
            "get_db() must return a generator (use 'yield', not 'return')"
        )

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_get_db_yields_session(self):
        from backend.app.database import get_db

        gen = get_db()
        session = next(gen)

        assert session is not None, "get_db() must yield a non-None session"

        assert hasattr(session, "commit"), "Yielded object must have commit()"
        assert hasattr(session, "rollback"), "Yielded object must have rollback()"
        assert hasattr(session, "close"), "Yielded object must have close()"

        try:
            next(gen)
        except StopIteration:
            pass

    @patch("backend.app.config.DATABASE_URL", SQLITE_MEMORY_URL)
    def test_get_db_closes_session_after_use(self):
        from backend.app.database import get_db

        real_session = MagicMock()

        with patch(
            "backend.app.database.SessionLocal", return_value=real_session
        ):
            gen = get_db()
            yielded = next(gen)

            assert yielded is real_session

            try:
                next(gen)
            except StopIteration:
                pass

            real_session.close.assert_called_once()
