"""Database engine and session management for SQLite."""

from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.db.models import Base

_engine = None
_SessionFactory = None


def get_engine(db_url: str = "sqlite:///./agentguard.db"):
    global _engine, _SessionFactory
    if _engine is None or str(_engine.url) != db_url:
        connect_args = {"check_same_thread": False} if db_url.startswith("sqlite") else {}
        _engine = create_engine(db_url, connect_args=connect_args, echo=False)
        _SessionFactory = sessionmaker(autocommit=False, autoflush=False, bind=_engine)
    return _engine


def get_session_factory(db_url: str = "sqlite:///./agentguard.db"):
    get_engine(db_url)
    return _SessionFactory


def init_db(db_url: str = "sqlite:///./agentguard.db") -> None:
    engine = get_engine(db_url)
    Base.metadata.create_all(bind=engine)


def reset_db(db_url: str = "sqlite:///./agentguard.db") -> None:
    engine = get_engine(db_url)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def get_db(db_url: str = "sqlite:///./agentguard.db") -> Generator[Session, None, None]:
    factory = get_session_factory(db_url)
    session = factory()
    try:
        yield session
    finally:
        session.close()

