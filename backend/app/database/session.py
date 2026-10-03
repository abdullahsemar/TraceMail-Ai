from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_db():
    Base.metadata.create_all(bind=engine)
    # Non-destructive column additions for existing SQLite databases
    if settings.DATABASE_URL.startswith("sqlite"):
        import sqlite3
        db_path = settings.DATABASE_URL.replace("sqlite:///", "")
        if db_path.startswith("./"):
            db_path = db_path[2:]
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            # Inspect existing columns on emails table
            cursor.execute("PRAGMA table_info(emails)")
            cols = {row[1] for row in cursor.fetchall()}
            
            new_columns = [
                ("review_status", "VARCHAR(32) DEFAULT 'UNREVIEWED'"),
                ("threat_probability", "FLOAT DEFAULT 0.0"),
                ("evidence_confidence", "FLOAT DEFAULT 0.0"),
                ("impact_score", "FLOAT DEFAULT 0.0")
            ]
            for col_name, col_def in new_columns:
                if col_name not in cols:
                    try:
                        cursor.execute(f"ALTER TABLE emails ADD COLUMN {col_name} {col_def}")
                    except Exception:
                        pass

            # Inspect existing columns on analysis_results table
            cursor.execute("PRAGMA table_info(analysis_results)")
            ar_cols = {row[1] for row in cursor.fetchall()}
            if "uncertainties" not in ar_cols:
                try:
                    cursor.execute("ALTER TABLE analysis_results ADD COLUMN uncertainties JSON DEFAULT '[]'")
                except Exception:
                    pass

            conn.commit()
            conn.close()
        except Exception:
            pass

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

