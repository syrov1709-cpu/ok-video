# models.py
from sqlalchemy import (
    create_engine,
    MetaData,
    Table,
    Column,
    Integer,
    String,
    inspect,
)

DB_PATH = "sites.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)
metadata = MetaData()

# таблиця сайтів
sites_table = Table(
    "sites",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("site_id", String, unique=True),
    Column("title", String),
    Column("content", String),
    Column("visits", Integer, default=0),
    Column("target_visits", Integer, default=0),
    Column("downloads", Integer, default=0),
    Column("video_url", String),
    Column("status", String, default="new"),
    Column("device_mode", String, default="all"),
    Column("custom_domain", String, nullable=True),
)

# таблиця адмінів
admins_table = Table(
    "admins",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("username", String, unique=True),
    Column("password_hash", String),
)


def init_db():
    # створюємо кожну таблицю окремо, якщо її ще нема
    sites_table.create(engine, checkfirst=True)
    admins_table.create(engine, checkfirst=True)

    # після того — доганяємо колонки, якщо ти додав нові в коді пізніше
    _ensure_site_columns()


def _ensure_site_columns():
    inspector = inspect(engine)
    cols = [c["name"] for c in inspector.get_columns("sites")]
    alters = []

    if "video_url" not in cols:
        alters.append("ALTER TABLE sites ADD COLUMN video_url TEXT")
    if "visits" not in cols:
        alters.append("ALTER TABLE sites ADD COLUMN visits INTEGER DEFAULT 0")
    if "status" not in cols:
        alters.append("ALTER TABLE sites ADD COLUMN status TEXT DEFAULT 'new'")
    if "device_mode" not in cols:
        alters.append("ALTER TABLE sites ADD COLUMN device_mode TEXT DEFAULT 'all'")

    if alters:
        with engine.begin() as conn:
            for stmt in alters:
                conn.exec_driver_sql(stmt)
