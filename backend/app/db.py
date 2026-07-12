from pathlib import Path
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from .config import settings
if settings.database_url.startswith('sqlite:///'):
    Path(settings.database_url.replace('sqlite:///', '', 1)).parent.mkdir(parents=True, exist_ok=True)
engine = create_engine(settings.database_url, connect_args={"check_same_thread": False, "timeout": 30} if settings.database_url.startswith('sqlite') else {}, future=True)
@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_connection, _):
    if settings.database_url.startswith('sqlite'):
        cur = dbapi_connection.cursor(); cur.execute("PRAGMA journal_mode=WAL"); cur.execute("PRAGMA busy_timeout=30000"); cur.close()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
class Base(DeclarativeBase): pass
def init_db():
    from . import models
    Base.metadata.create_all(bind=engine)
def db_health() -> bool:
    with engine.connect() as conn: conn.execute(text('SELECT 1'))
    return True
