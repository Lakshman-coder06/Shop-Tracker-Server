"""
shop_db.py  (SERVER SIDE - the real database code)
--------------------------------------------------
This is the original database.py, now running ONLY on the shop server.
The app on each PC no longer opens this file - it asks the server instead
(see the app's database.py). Two small edits vs. the old version: the
database location is configurable, and starter accounts must change their
PIN at first login.

Original description:
Handles all SQLite database setup and access for the
Thalapathi Studio.

For this first version we create the FULL database structure
(all 7 tables from the plan), but only 'users' and 'services'
are actively used by the app so far. The rest sit ready and
empty until we build Quick Job Entry, Expenses, etc. in later
steps. This avoids having to change the database shape later.
"""

import sqlite3
import hashlib
import os
from contextlib import contextmanager
from datetime import datetime

# Where the ONE shared database lives. Set the SHOPTRACKER_DB environment
# variable to change it (e.g. to a mounted disk on a cloud host); by default
# it sits in a "data" folder right next to the server.
_DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_FILE = os.environ.get("SHOPTRACKER_DB") or os.path.join(_DEFAULT_DATA_DIR, "shop_tracker.db")
os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)


class DuplicateNameError(Exception):
    """Raised when a service (or other uniquely-named record) already
    exists, so the UI can show a clean message instead of a raw
    sqlite3.IntegrityError."""
    pass


class LastAdminError(Exception):
    """Raised when an action would deactivate the only remaining active
    Admin account, which would permanently lock everyone out of Admin
    functions. The action is refused before it happens."""
    pass


def get_connection():
    """Create and return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row  # lets us read columns by name, e.g. row["name"]
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 8000")  # wait up to 8s for a lock instead of failing instantly
    conn.execute("PRAGMA journal_mode = WAL")   # readers no longer block writers or vice versa
    return conn


@contextmanager
def db_write():
    """
    THE FIX for 'database is locked': every write in this file used to
    follow the pattern conn = get_connection(); cur.execute(...);
    conn.commit(); conn.close() - written in that order, with nothing
    catching an error from execute(). If execute() raised (e.g. a UNIQUE
    constraint violation from a duplicate service name), commit() and
    close() were both skipped, leaking an open connection holding a lock.
    Enough of those piling up is exactly what produced "database is locked".

    This context manager guarantees the connection is ALWAYS closed - on
    success (commit) or failure (rollback then re-raise) - by putting the
    close in a finally block. Every write function below uses this
    instead of managing its own connection lifecycle by hand.

    Usage:
        with db_write() as (conn, cur):
            cur.execute("INSERT INTO ...", (...))
            # commit happens automatically if this block doesn't raise
    """
    conn = get_connection()
    cur = conn.cursor()
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def hash_pin(pin: str) -> str:
    """Turn a PIN into a scrambled string so raw PINs are never stored in the database."""
    return hashlib.sha256(pin.encode("utf-8")).hexdigest()


def init_db():
    """Create all tables if they don't already exist, and seed starter data."""
    conn = get_connection()
    cur = conn.cursor()

    # ---------- USERS (workers / supervisor / admin) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            pin_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('worker', 'supervisor', 'admin')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # ---------- WORKER SESSIONS (NEW in Phase 1) ----------
    # One row per login. logout_time/duration_seconds stay NULL until the
    # worker logs out (or closes the app, which we also catch).
    cur.execute("""
        CREATE TABLE IF NOT EXISTS worker_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            worker_id INTEGER NOT NULL,
            login_time TEXT NOT NULL,
            logout_time TEXT,
            duration_seconds INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (worker_id) REFERENCES users(id)
        )
    """)

    # ---------- SERVICES (Xerox, Printing, Passport Photo, ...) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            rate REAL NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)

    # ---------- TRANSACTIONS (built in a later step) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_code TEXT NOT NULL UNIQUE,
            worker_id INTEGER NOT NULL,
            service_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Completed',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (worker_id) REFERENCES users(id),
            FOREIGN KEY (service_id) REFERENCES services(id)
        )
    """)

    # ---------- EXPENSES (built in a later step) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            expense_code TEXT NOT NULL UNIQUE,
            worker_id INTEGER NOT NULL,
            purpose TEXT NOT NULL,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (worker_id) REFERENCES users(id)
        )
    """)

    # ---------- APPLICATION ACTIVITY (built in a later step) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS application_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            worker_id INTEGER NOT NULL,
            app_name TEXT NOT NULL,
            start_time TEXT NOT NULL,
            end_time TEXT,
            duration_seconds INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (worker_id) REFERENCES users(id)
        )
    """)

    # ---------- DAILY CLOSING (built in a later step) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS daily_closing (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            closing_date TEXT NOT NULL UNIQUE,
            expected_cash REAL NOT NULL,
            actual_cash REAL,
            difference REAL,
            closed_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (closed_by) REFERENCES users(id)
        )
    """)

    # ---------- AUDIT LOGS (built in a later step) ----------
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT NOT NULL,
            record_id INTEGER NOT NULL,
            field_changed TEXT,
            old_value TEXT,
            new_value TEXT,
            changed_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (changed_by) REFERENCES users(id)
        )
    """)

    conn.commit()
    _migrate_schema(conn)
    _seed_starter_data(conn)
    conn.close()


def _migrate_schema(conn):
    """
    Safe, additive-only migration. Never drops or renames anything and
    never touches existing rows - only adds new columns if they don't
    already exist, and adds new default services if missing by name.
    Existing data (activity history, sessions, etc.) is preserved untouched.
    """
    cur = conn.cursor()

    # --- application_activity (Phase 1.5) ---
    cur.execute("PRAGMA table_info(application_activity)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "process_name" not in existing_cols:
        cur.execute("ALTER TABLE application_activity ADD COLUMN process_name TEXT")
    if "computer_name" not in existing_cols:
        cur.execute("ALTER TABLE application_activity ADD COLUMN computer_name TEXT")
    if "windows_username" not in existing_cols:
        cur.execute("ALTER TABLE application_activity ADD COLUMN windows_username TEXT")

    # --- transactions (Phase 2: Quick Job Entry) ---
    cur.execute("PRAGMA table_info(transactions)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "customer_reference" not in existing_cols:
        cur.execute("ALTER TABLE transactions ADD COLUMN customer_reference TEXT")
    if "rate" not in existing_cols:
        cur.execute("ALTER TABLE transactions ADD COLUMN rate REAL")
    if "notes" not in existing_cols:
        cur.execute("ALTER TABLE transactions ADD COLUMN notes TEXT")
    if "payment_status" not in existing_cols:
        cur.execute("ALTER TABLE transactions ADD COLUMN payment_status TEXT DEFAULT 'Paid'")

    # --- expenses (Phase 2: Expense Entry) ---
    cur.execute("PRAGMA table_info(expenses)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "category" not in existing_cols:
        cur.execute("ALTER TABLE expenses ADD COLUMN category TEXT")
    if "notes" not in existing_cols:
        cur.execute("ALTER TABLE expenses ADD COLUMN notes TEXT")

    # --- users (Phase 3: worker management, PIN reset, temp-PIN flow) ---
    cur.execute("PRAGMA table_info(users)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "status" not in existing_cols:
        # Backfill from the existing active flag so nobody's login state changes
        cur.execute("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'Active'")
        cur.execute("UPDATE users SET status = CASE WHEN active = 1 THEN 'Active' ELSE 'Inactive' END")
    if "employee_id" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN employee_id TEXT")
    if "must_change_pin" not in existing_cols:
        cur.execute("ALTER TABLE users ADD COLUMN must_change_pin INTEGER DEFAULT 0")

    # --- transactions (Phase 3: advance/balance for Pending jobs) ---
    cur.execute("PRAGMA table_info(transactions)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "advance_amount" not in existing_cols:
        cur.execute("ALTER TABLE transactions ADD COLUMN advance_amount REAL DEFAULT 0")

    # --- application_activity (Phase 3: foreground-window title, when useful) ---
    cur.execute("PRAGMA table_info(application_activity)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "window_title" not in existing_cols:
        cur.execute("ALTER TABLE application_activity ADD COLUMN window_title TEXT")

    # --- daily_closing (v5: Opening Cash must persist across reopens - it
    # was being calculated into expected_cash but never itself saved) ---
    cur.execute("PRAGMA table_info(daily_closing)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "opening_cash" not in existing_cols:
        cur.execute("ALTER TABLE daily_closing ADD COLUMN opening_cash REAL DEFAULT 0")

    # --- payments (v5: proper day-based advance/balance accounting) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id INTEGER NOT NULL,
            amount REAL NOT NULL,
            payment_method TEXT NOT NULL,
            recorded_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (transaction_id) REFERENCES transactions(id),
            FOREIGN KEY (recorded_by) REFERENCES users(id)
        )
    """)
    # One-time backfill: every OLD transaction (created before the payments
    # table existed) recorded its money in a single payment_status/amount
    # snapshot with no day-by-day breakdown. So today's Sales/Cash/UPI
    # figures (which now come from the payments table) don't silently drop
    # to zero for old data, back-fill exactly one payment per pre-existing
    # transaction that already shows money received - dated at the
    # transaction's own created_at (the best information available for
    # data that predates this table), for whatever amount had already been
    # marked as received (the advance if unpaid, the full amount if paid).
    # This runs harmlessly every startup - it explicitly skips any
    # transaction that already has a payments row, so it is safe to run
    # more than once and never creates duplicates.
    cur.execute("""
        SELECT t.id, t.amount, t.advance_amount, t.payment_method, t.payment_status, t.created_at, t.worker_id
        FROM transactions t
        LEFT JOIN payments p ON p.transaction_id = t.id
        WHERE p.id IS NULL AND t.status != 'Cancelled'
    """)
    to_backfill = cur.fetchall()
    for row in to_backfill:
        if row["payment_status"] == "Paid":
            backfill_amount = row["amount"]
        elif (row["advance_amount"] or 0) > 0:
            backfill_amount = row["advance_amount"]
        else:
            backfill_amount = 0
        if backfill_amount and backfill_amount > 0:
            cur.execute(
                "INSERT INTO payments (transaction_id, amount, payment_method, recorded_by, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (row["id"], backfill_amount, row["payment_method"], row["worker_id"], row["created_at"]),
            )

    # --- enquiries (v5: Part 12) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS enquiries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT,
            description TEXT,
            priority TEXT NOT NULL DEFAULT 'Medium',
            status TEXT NOT NULL DEFAULT 'Open',
            created_by INTEGER NOT NULL,
            assigned_to INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (assigned_to) REFERENCES users(id)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS enquiry_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            enquiry_id INTEGER NOT NULL,
            comment TEXT NOT NULL,
            created_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (enquiry_id) REFERENCES enquiries(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    """)

    # --- todos (v5: Part 13) ---
    cur.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            priority TEXT NOT NULL DEFAULT 'Medium',
            status TEXT NOT NULL DEFAULT 'Pending',
            due_date TEXT,
            created_by INTEGER NOT NULL,
            assigned_to INTEGER,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT,
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (assigned_to) REFERENCES users(id)
        )
    """)

    conn.commit()

    # --- services: add any new ones that don't already exist by name ---
    # (Phase 1 seeded a shorter list; Phase 2 needs a fuller one. We only
    # ADD missing names here - nothing is renamed or removed, so any rates
    # you've already customized are untouched.)
    now = datetime.now().isoformat()
    fuller_service_list = [
        ("Xerox B&W", 2), ("Xerox Colour", 10), ("Print B&W", 5), ("Print Colour", 10),
        ("Passport Photo", 80), ("Photo Print", 15), ("Lamination", 20), ("Scanning", 10),
        ("Invitation Design", 200), ("Invitation Printing", 15), ("Album Design", 500), ("Other", 0),
    ]
    cur.execute("SELECT name FROM services")
    existing_names = {row[0] for row in cur.fetchall()}
    for name, rate in fuller_service_list:
        if name not in existing_names:
            cur.execute(
                "INSERT INTO services (name, rate, active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
                (name, rate, now, now),
            )
    conn.commit()


def _seed_starter_data(conn):
    """Add default workers, only if the users table is empty. (Services are
    seeded additively inside _migrate_schema, which always runs first.)"""
    cur = conn.cursor()
    now = datetime.now().isoformat()

    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        default_users = [
            ("Worker 1", "1111", "worker"),
            ("Worker 2", "2222", "worker"),
            ("Worker 3", "3333", "worker"),
            ("Admin", "9999", "admin"),
        ]
        for name, pin, role in default_users:
            cur.execute(
                "INSERT INTO users (name, pin_hash, role, active, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?)",
                (name, hash_pin(pin), role, now, now),
            )
        # SERVER SAFETY: the starter PINs (1111/2222/3333/9999) are public
        # knowledge, so every starter account is forced to choose a new PIN
        # the first time it logs in.
        cur.execute("UPDATE users SET must_change_pin = 1")

    conn.commit()


def get_active_workers():
    """Return all active users (workers, supervisor, admin) for the login screen."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, role FROM users WHERE active = 1 ORDER BY role, name")
    rows = cur.fetchall()
    conn.close()
    return rows


def verify_login(user_id: int, pin: str):
    """Check a PIN against one user's stored PIN hash. Returns the user row, or None if wrong."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,))
    user = cur.fetchone()
    conn.close()
    if user and user["pin_hash"] == hash_pin(pin):
        return user
    return None


def authenticate(name: str, pin: str):
    """Username+PIN login for the premium login screen - no worker list is
    ever shown or needed. Matches the name case-insensitively and after
    trimming whitespace, so 'worker 1', 'Worker 1', and ' Worker 1 ' all
    work. Returns the user row on success, or None on any failure (wrong
    name OR wrong PIN) - deliberately the SAME return value either way, so
    a mistyped name never reveals whether that name exists in the system."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE LOWER(TRIM(name)) = LOWER(?) AND active = 1", (name.strip(),))
    user = cur.fetchone()
    conn.close()
    if user and user["pin_hash"] == hash_pin(pin):
        return user
    return None


def get_today_summary(worker_id: int = None):
    """
    Today's numbers. Pass worker_id to scope everything to just that
    worker ("My Sales" on the Worker dashboard) - leave it None for
    shop-wide totals (Admin dashboard only).
      - jobs: count of all non-cancelled transactions CREATED today
        (a job counts as "today's work" the day it was entered, regardless
        of when it eventually gets paid off)
      - sales/cash/upi: sum of payments RECEIVED today, joined back to
        their transaction only to exclude Cancelled jobs and to scope by
        worker. This is the fix for Part 6: an advance taken on Day 1 and
        a balance collected on Day 2 now correctly show up as separate
        days' money, instead of both being attributed to the day the job
        was created.
      - expenses: all expenses recorded today, any payment source
      - expected_drawer: cash actually collected today minus CASH
        expenses today (a UPI expense doesn't remove physical cash)
    """
    conn = get_connection()
    cur = conn.cursor()
    w = " AND t.worker_id = ?" if worker_id is not None else ""
    w_e = " AND worker_id = ?" if worker_id is not None else ""
    p = (worker_id,) if worker_id is not None else ()

    cur.execute(f"""
        SELECT COUNT(*) FROM transactions t
        WHERE date(t.created_at) = date('now', 'localtime') AND t.status != 'Cancelled' {w}
    """, p)
    jobs = cur.fetchone()[0]

    cur.execute(f"""
        SELECT COALESCE(SUM(pay.amount), 0)
        FROM payments pay
        JOIN transactions t ON t.id = pay.transaction_id
        WHERE date(pay.created_at) = date('now', 'localtime') AND t.status != 'Cancelled' {w}
    """, p)
    sales = cur.fetchone()[0]

    cur.execute(f"""
        SELECT COALESCE(SUM(pay.amount), 0)
        FROM payments pay
        JOIN transactions t ON t.id = pay.transaction_id
        WHERE date(pay.created_at) = date('now', 'localtime') AND t.status != 'Cancelled'
          AND pay.payment_method = 'Cash' {w}
    """, p)
    cash = cur.fetchone()[0]

    cur.execute(f"""
        SELECT COALESCE(SUM(pay.amount), 0)
        FROM payments pay
        JOIN transactions t ON t.id = pay.transaction_id
        WHERE date(pay.created_at) = date('now', 'localtime') AND t.status != 'Cancelled'
          AND pay.payment_method = 'UPI' {w}
    """, p)
    upi = cur.fetchone()[0]

    cur.execute(f"""
        SELECT COALESCE(SUM(amount), 0) FROM expenses
        WHERE date(created_at) = date('now', 'localtime') {w_e}
    """, p)
    expenses_all = cur.fetchone()[0]

    cur.execute(f"""
        SELECT COALESCE(SUM(amount), 0) FROM expenses
        WHERE date(created_at) = date('now', 'localtime') AND payment_method = 'Cash' {w_e}
    """, p)
    cash_expenses = cur.fetchone()[0]

    conn.close()
    return {
        "jobs": jobs,
        "sales": sales,
        "cash": cash,
        "upi": upi,
        "expenses": expenses_all,
        "expected_drawer": cash - cash_expenses,
    }


def get_worker_performance_today():
    """One row per active worker with today's numbers - powers the Admin
    dashboard's 'Worker Performance' section. Uses get_today_summary()
    under the hood so the math is identical to what each worker sees on
    their own dashboard."""
    workers = get_active_workers()
    result = []
    for w in workers:
        if w["role"] == "admin":
            continue  # Admin doesn't do jobs - no point showing a zeroed row
        summary = get_today_summary(worker_id=w["id"])
        result.append({"worker_id": w["id"], "worker_name": w["name"], **summary})
    return result


def get_active_services():
    """All active services, for the Service dropdown in New Job. Ordered by
    id so they appear in the same sensible grouping they were seeded in."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name, rate FROM services WHERE active = 1 ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


# =====================================================================
# PHASE 1 — Worker session tracking
# =====================================================================

def start_worker_session(worker_id: int) -> int:
    """Record a new login session for a worker. Returns the new session's id."""
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO worker_sessions (worker_id, login_time, created_at) VALUES (?, ?, ?)",
            (worker_id, now, now),
        )
        session_id = cur.lastrowid
    return session_id


def end_worker_session(session_id: int):
    """Fill in the logout time and duration for a session that just ended."""
    if session_id is None:
        return
    with db_write() as (conn, cur):
        cur.execute("SELECT login_time, logout_time FROM worker_sessions WHERE id = ?", (session_id,))
        row = cur.fetchone()
        if row is None or row["logout_time"] is not None:
            # Either the session doesn't exist, or it was already closed once
            # (this can happen if logout AND window-close both fire - harmless).
            return
        login_time = datetime.fromisoformat(row["login_time"])
        now = datetime.now()
        duration = int((now - login_time).total_seconds())
        cur.execute(
            "UPDATE worker_sessions SET logout_time = ?, duration_seconds = ? WHERE id = ?",
            (now.isoformat(timespec="seconds"), duration, session_id),
        )


# =====================================================================
# PHASE 1.5 — Application activity tracking (dynamic, general-purpose)
# (still writes into the same application_activity table - no new table)
# =====================================================================

def log_activity_start(worker_id: int, app_name: str, process_name: str,
                        start_time: datetime, computer_name: str = None,
                        windows_username: str = None, window_title: str = None) -> int:
    """Record that an application/window just started. Returns the new row's id.
    This fires roughly every 2 seconds while the monitor is running, so it's
    one of the highest-traffic writes in the app - the safe db_write()
    wrapper matters most here."""
    ts = start_time.isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO application_activity "
            "(worker_id, app_name, process_name, start_time, computer_name, windows_username, window_title, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (worker_id, app_name, process_name, ts, computer_name, windows_username, window_title, ts),
        )
        row_id = cur.lastrowid
    return row_id


def log_activity_end(row_id: int, start_time: datetime, end_time: datetime):
    """Fill in the end time and duration once an application/window closes."""
    duration = int((end_time - start_time).total_seconds())
    with db_write() as (conn, cur):
        cur.execute(
            "UPDATE application_activity SET end_time = ?, duration_seconds = ? WHERE id = ?",
            (end_time.isoformat(timespec="seconds"), duration, row_id),
        )


def get_recent_activity(limit: int = 25, worker_id: int = None):
    """Most recent activity rows (newest first), optionally for one worker. Used by the Live Activity screen."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT aa.*, u.name AS worker_name
        FROM application_activity aa
        JOIN users u ON u.id = aa.worker_id
    """
    params = []
    if worker_id is not None:
        query += " WHERE aa.worker_id = ?"
        params.append(worker_id)
    query += " ORDER BY aa.start_time DESC LIMIT ?"
    params.append(limit)
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_activity_history(date_filter: str = None, worker_id: int = None,
                          app_name: str = None, status_filter: str = None):
    """
    Filtered activity rows for the History screen.
    date_filter: None | 'today' | 'yesterday' | 'week'
    status_filter: None | 'open' (no end_time yet) | 'closed'
    """
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT aa.*, u.name AS worker_name
        FROM application_activity aa
        JOIN users u ON u.id = aa.worker_id
        WHERE 1=1
    """
    params = []

    if date_filter == "today":
        query += " AND date(aa.start_time) = date('now', 'localtime')"
    elif date_filter == "yesterday":
        query += " AND date(aa.start_time) = date('now', '-1 day', 'localtime')"
    elif date_filter == "week":
        query += " AND date(aa.start_time) >= date('now', '-7 day', 'localtime')"

    if worker_id is not None:
        query += " AND aa.worker_id = ?"
        params.append(worker_id)

    if app_name:
        query += " AND aa.app_name = ?"
        params.append(app_name)

    if status_filter == "open":
        query += " AND aa.end_time IS NULL"
    elif status_filter == "closed":
        query += " AND aa.end_time IS NOT NULL"

    query += " ORDER BY aa.start_time DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_activity_by_id(activity_id: int):
    """Full detail for one activity row (for the Activity Details dialog)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT aa.*, u.name AS worker_name
        FROM application_activity aa
        JOIN users u ON u.id = aa.worker_id
        WHERE aa.id = ?
    """, (activity_id,))
    row = cur.fetchone()
    conn.close()
    return row


def get_distinct_activity_apps():
    """Every distinct application name ever recorded - for the History screen's Application filter."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT app_name FROM application_activity ORDER BY app_name")
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows


def get_last_activity_saved():
    """Timestamp of the most recently saved activity row, for the Diagnostics screen."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT created_at FROM application_activity ORDER BY id DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row["created_at"] if row else None


def check_db_connection() -> bool:
    """Simple health check for the Diagnostics screen."""
    try:
        conn = get_connection()
        conn.execute("SELECT 1")
        conn.close()
        return True
    except Exception:
        return False

# =====================================================================
# PHASE 2 — Quick Job Entry, Transactions, Expenses, Pending Records,
# Daily Closing. All of this reuses the tables already created above.
# =====================================================================

def log_audit(table_name: str, record_id: int, field_changed: str,
              old_value, new_value, changed_by: int):
    """Every correction (e.g. marking a job Completed or Paid) leaves a
    permanent trace here - nothing is ever silently overwritten."""
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO audit_logs (table_name, record_id, field_changed, old_value, new_value, changed_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (table_name, record_id, field_changed, str(old_value), str(new_value), changed_by, now),
        )


def _next_daily_code(cur, table: str, code_column: str, prefix: str) -> str:
    """JOB-20260902-0001 style code: prefix + today's date + a daily sequence."""
    today_str = datetime.now().strftime("%Y%m%d")
    cur.execute(f"SELECT COUNT(*) FROM {table} WHERE date(created_at) = date('now', 'localtime')")
    seq = cur.fetchone()[0] + 1
    return f"{prefix}-{today_str}-{seq:04d}"


# ---- Transactions (New Job / Transactions / Pending Records) ----

def create_transaction(worker_id: int, service_id: int, quantity: int,
                        payment_method: str, status: str,
                        customer_reference: str = None, notes: str = None,
                        advance_amount: float = 0):
    """
    Saves one job. SECURITY: this function does NOT accept a rate from the
    caller at all - the rate is always looked up here, directly from the
    services table, using service_id. This is deliberate: shop rates are
    fixed by Admin via Service Management, and a worker (or anything
    calling this function) must never be able to submit an arbitrary
    price by passing a different number - there is no parameter here for
    that number to even go in. The rate found at the moment of saving is
    stamped onto the transaction (transactions.rate) so that a LATER rate
    change by Admin never alters this transaction's amount - only future
    jobs see a new price.

    Also records whatever money actually changed hands right now as a row
    in the payments table (dated today) - this is what makes Daily
    Closing and the Dashboard correctly count an advance on the day it
    was actually taken, and a later balance payment on the day IT was
    actually taken, instead of attributing everything to the job's
    creation date.
      - status == 'Completed': assumed paid in full right now -> one
        payment for the full amount.
      - status in ('Pending', 'In Progress') with advance_amount > 0: one
        payment for just the advance.
      - status in ('Pending', 'In Progress') with no advance: no payment
        recorded yet - nothing has been collected.
    payment_status is kept as a simple denormalized snapshot ('Paid' /
    'Partial' / 'Unpaid') for fast display, but is always derived from the
    real payments recorded, via _recalculate_payment_status().
    Returns (id, transaction_code).
    """
    now = datetime.now().isoformat(timespec="seconds")
    code = None
    row_id = None
    with db_write() as (conn, cur):
        cur.execute("SELECT rate FROM services WHERE id = ?", (service_id,))
        service_row = cur.fetchone()
        if service_row is None:
            raise ValueError(f"Service id {service_id} does not exist.")
        rate = service_row["rate"]  # the ONLY source of truth for price - never trust a caller-supplied rate

        amount = round(quantity * rate, 2)
        code = _next_daily_code(cur, "transactions", "transaction_code", "JOB")
        cur.execute(
            "INSERT INTO transactions "
            "(transaction_code, worker_id, service_id, quantity, amount, rate, payment_method, "
            " status, payment_status, customer_reference, notes, advance_amount, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Unpaid', ?, ?, ?, ?, ?)",
            (code, worker_id, service_id, quantity, amount, rate, payment_method,
             status, customer_reference, notes, advance_amount, now, now),
        )
        row_id = cur.lastrowid

        collected_now = amount if status == "Completed" else (advance_amount or 0)
        if collected_now > 0:
            cur.execute(
                "INSERT INTO payments (transaction_id, amount, payment_method, recorded_by, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (row_id, collected_now, payment_method, worker_id, now),
            )
        _recalculate_payment_status(cur, row_id)
    return row_id, code


def _recalculate_payment_status(cur, transaction_id: int):
    """Sets a transaction's payment_status to Paid/Partial/Unpaid based on
    the ACTUAL sum of its payments vs its total amount. Called any time a
    payment is added, inside the same db_write() block as that insert, so
    it's always consistent with what's really been collected."""
    cur.execute("SELECT amount FROM transactions WHERE id = ?", (transaction_id,))
    total = cur.fetchone()["amount"]
    cur.execute("SELECT COALESCE(SUM(amount), 0) AS paid FROM payments WHERE transaction_id = ?", (transaction_id,))
    paid = cur.fetchone()["paid"]
    if paid >= total and total > 0:
        status = "Paid"
    elif paid > 0:
        status = "Partial"
    else:
        status = "Unpaid"
    cur.execute("UPDATE transactions SET payment_status = ? WHERE id = ?", (status, transaction_id))


def record_payment(transaction_id: int, amount: float, payment_method: str, recorded_by: int):
    """Records money actually received against an existing job, dated NOW
    (not backdated to when the job was created) - this is how a balance
    payment collected days after the original advance gets counted on the
    day it actually came in. Replaces the old mark_transaction_paid, which
    only flipped a status flag without recording when/how the money
    arrived. Returns the new payment's id."""
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute("SELECT payment_status FROM transactions WHERE id = ?", (transaction_id,))
        row = cur.fetchone()
        if row is None:
            return None
        old_status = row["payment_status"]
        cur.execute(
            "INSERT INTO payments (transaction_id, amount, payment_method, recorded_by, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (transaction_id, amount, payment_method, recorded_by, now),
        )
        payment_id = cur.lastrowid
        _recalculate_payment_status(cur, transaction_id)
        cur.execute("SELECT payment_status FROM transactions WHERE id = ?", (transaction_id,))
        new_status = cur.fetchone()["payment_status"]
    if new_status != old_status:
        log_audit("transactions", transaction_id, "payment_status", old_status, new_status, recorded_by)
    return payment_id


def get_transaction_payments(transaction_id: int):
    """Every payment recorded against one job, for Activity Details / receipts."""
    with db_write() as (conn, cur):
        cur.execute("SELECT * FROM payments WHERE transaction_id = ? ORDER BY created_at", (transaction_id,))
        return cur.fetchall()


def get_transactions(date_filter: str = "today", worker_id: int = None):
    """date_filter: 'today' | 'yesterday' | 'week' | None (all). Each row
    includes paid_amount and balance, computed from actual payments -
    not just the original advance_amount snapshot."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT t.*, u.name AS worker_name, s.name AS service_name,
               COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.transaction_id = t.id), 0) AS paid_amount
        FROM transactions t
        JOIN users u ON u.id = t.worker_id
        JOIN services s ON s.id = t.service_id
        WHERE 1=1
    """
    params = []
    if date_filter == "today":
        query += " AND date(t.created_at) = date('now', 'localtime')"
    elif date_filter == "yesterday":
        query += " AND date(t.created_at) = date('now', '-1 day', 'localtime')"
    elif date_filter == "week":
        query += " AND date(t.created_at) >= date('now', '-7 day', 'localtime')"
    if worker_id is not None:
        query += " AND t.worker_id = ?"
        params.append(worker_id)
    query += " ORDER BY t.created_at DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_today_transaction_totals():
    """Totals block shown at the top of the Transactions screen."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT COUNT(*), COALESCE(SUM(CASE WHEN payment_status='Paid' THEN amount ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN payment_status='Paid' AND payment_method='Cash' THEN amount ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN payment_status='Paid' AND payment_method='UPI' THEN amount ELSE 0 END), 0)
        FROM transactions
        WHERE date(created_at) = date('now', 'localtime') AND status != 'Cancelled'
    """)
    jobs, sales, cash, upi = cur.fetchone()
    conn.close()
    return {"jobs": jobs, "sales": sales, "cash": cash, "upi": upi}


def get_pending_transactions(worker_id: int = None):
    """Anything not yet fully Paid (and not Cancelled) - what the Pending
    Records screen shows. balance is computed from actual payments
    received, not just the original advance. Pass worker_id to scope to
    one worker's own pending jobs only."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT t.*, u.name AS worker_name, s.name AS service_name,
               COALESCE((SELECT SUM(p.amount) FROM payments p WHERE p.transaction_id = t.id), 0) AS paid_amount
        FROM transactions t
        JOIN users u ON u.id = t.worker_id
        JOIN services s ON s.id = t.service_id
        WHERE t.status != 'Cancelled' AND NOT (t.status = 'Completed' AND t.payment_status = 'Paid')
    """
    params = []
    if worker_id is not None:
        query += " AND t.worker_id = ?"
        params.append(worker_id)
    query += " ORDER BY t.created_at DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def mark_transaction_completed(transaction_id: int, changed_by: int):
    with db_write() as (conn, cur):
        cur.execute("SELECT status FROM transactions WHERE id = ?", (transaction_id,))
        row = cur.fetchone()
        if row is None:
            return
        old_status = row["status"]
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute("UPDATE transactions SET status = 'Completed', updated_at = ? WHERE id = ?", (now, transaction_id))
    if old_status != "Completed":
        log_audit("transactions", transaction_id, "status", old_status, "Completed", changed_by)


def mark_transaction_in_progress(transaction_id: int, changed_by: int):
    with db_write() as (conn, cur):
        cur.execute("SELECT status FROM transactions WHERE id = ?", (transaction_id,))
        row = cur.fetchone()
        if row is None:
            return
        old_status = row["status"]
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute("UPDATE transactions SET status = 'In Progress', updated_at = ? WHERE id = ?", (now, transaction_id))
    if old_status != "In Progress":
        log_audit("transactions", transaction_id, "status", old_status, "In Progress", changed_by)


def cancel_transaction(transaction_id: int, reason: str, changed_by: int):
    """Soft-cancel only - the row is never deleted, just marked Cancelled
    and excluded from financial totals and Pending Records. Matches the
    'prefer soft-delete for financial records' rule."""
    with db_write() as (conn, cur):
        cur.execute("SELECT status FROM transactions WHERE id = ?", (transaction_id,))
        row = cur.fetchone()
        if row is None:
            return
        old_status = row["status"]
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "UPDATE transactions SET status = 'Cancelled', notes = COALESCE(notes || ' | ', '') || ?, updated_at = ? WHERE id = ?",
            (f"Cancelled: {reason}", now, transaction_id),
        )
    log_audit("transactions", transaction_id, "status", old_status, f"Cancelled ({reason})", changed_by)


def mark_transaction_paid(transaction_id: int, changed_by: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT payment_status FROM transactions WHERE id = ?", (transaction_id,))
    row = cur.fetchone()
    if row is None:
        conn.close()
        return
    old_status = row["payment_status"]
    now = datetime.now().isoformat(timespec="seconds")
    cur.execute("UPDATE transactions SET payment_status = 'Paid', updated_at = ? WHERE id = ?", (now, transaction_id))
    conn.commit()
    conn.close()
    if old_status != "Paid":
        log_audit("transactions", transaction_id, "payment_status", old_status, "Paid", changed_by)


# ---- Expenses ----

def create_expense(worker_id: int, category: str, reason: str, amount: float,
                    payment_method: str, notes: str = None):
    """Returns (id, expense_code)."""
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        code = _next_daily_code(cur, "expenses", "expense_code", "EXP")
        cur.execute(
            "INSERT INTO expenses "
            "(expense_code, worker_id, category, purpose, amount, payment_method, status, notes, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'Recorded', ?, ?, ?)",
            (code, worker_id, category, reason, amount, payment_method, notes, now, now),
        )
        row_id = cur.lastrowid
    return row_id, code


def get_expenses_today(worker_id: int = None):
    """Pass worker_id to scope to one worker's own expenses only (fixes a
    privacy gap where the Expense screen's running list showed everyone's
    expenses, not just the logged-in worker's)."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT e.*, u.name AS worker_name
        FROM expenses e
        JOIN users u ON u.id = e.worker_id
        WHERE date(e.created_at) = date('now', 'localtime')
    """
    params = []
    if worker_id is not None:
        query += " AND e.worker_id = ?"
        params.append(worker_id)
    query += " ORDER BY e.created_at DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


# ---- Daily Closing ----

def get_daily_totals_for_closing():
    """Cash received today, UPI received today (from actual payments, so an
    advance/balance split across days is counted correctly), and CASH-ONLY
    expenses today - exactly the inputs the Daily Closing formula needs."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT COALESCE(SUM(CASE WHEN pay.payment_method='Cash' THEN pay.amount ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN pay.payment_method='UPI' THEN pay.amount ELSE 0 END), 0)
        FROM payments pay
        JOIN transactions t ON t.id = pay.transaction_id
        WHERE date(pay.created_at) = date('now', 'localtime') AND t.status != 'Cancelled'
    """)
    cash_sales, upi_sales = cur.fetchone()

    cur.execute("""
        SELECT COALESCE(SUM(amount), 0) FROM expenses
        WHERE date(created_at) = date('now', 'localtime') AND payment_method = 'Cash'
    """)
    cash_expenses = cur.fetchone()[0]
    conn.close()
    return {"cash_sales": cash_sales, "upi_sales": upi_sales, "cash_expenses": cash_expenses}


def get_daily_closing(closing_date: str = None):
    """Fetch a previously saved closing record for a date (defaults to today), if any."""
    conn = get_connection()
    cur = conn.cursor()
    if closing_date:
        cur.execute("SELECT * FROM daily_closing WHERE closing_date = ?", (closing_date,))
    else:
        cur.execute("SELECT * FROM daily_closing WHERE closing_date = date('now', 'localtime')")
    row = cur.fetchone()
    conn.close()
    return row


def save_daily_closing(opening_cash: float, expected_cash: float, actual_cash: float,
                        difference: float, closed_by: int):
    """One row per date - saving the same day again updates that row rather
    than creating a duplicate (closing_date is UNIQUE). opening_cash is now
    persisted (previously it was only used to calculate expected_cash but
    never itself saved, so reopening the screen lost it - this was a real
    bug, not just a nice-to-have)."""
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute("""
            INSERT INTO daily_closing (closing_date, opening_cash, expected_cash, actual_cash, difference, closed_by, created_at)
            VALUES (date('now', 'localtime'), ?, ?, ?, ?, ?, ?)
            ON CONFLICT(closing_date) DO UPDATE SET
                opening_cash = excluded.opening_cash,
                expected_cash = excluded.expected_cash,
                actual_cash = excluded.actual_cash,
                difference = excluded.difference,
                closed_by = excluded.closed_by
        """, (opening_cash, expected_cash, actual_cash, difference, closed_by, now))


# =====================================================================
# PHASE 3 — Worker management, service/rate management, PIN security,
# audit log viewing, and per-app usage totals (for the redesigned
# foreground-window Activity screen).
# =====================================================================

# ---- Worker management (Admin only) ----

def get_all_workers_admin():
    """Every worker/admin account regardless of active status - Worker
    Management needs to show Inactive/On Leave people too, not just who
    can currently log in."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY role, name")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_user_by_id(user_id: int):
    """A fresh, single-user lookup (e.g. for Settings' account details, in
    case status/role changed since login)."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row


def create_worker(name: str, pin: str, role: str, employee_id: str = None):
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO users (name, pin_hash, role, active, status, employee_id, must_change_pin, created_at, updated_at) "
            "VALUES (?, ?, ?, 1, 'Active', ?, 0, ?, ?)",
            (name, hash_pin(pin), role, employee_id, now, now),
        )
        row_id = cur.lastrowid
    return row_id


def update_worker(user_id: int, name: str, employee_id: str, changed_by: int):
    with db_write() as (conn, cur):
        cur.execute("SELECT name, employee_id FROM users WHERE id = ?", (user_id,))
        old = cur.fetchone()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute(
            "UPDATE users SET name = ?, employee_id = ?, updated_at = ? WHERE id = ?",
            (name, employee_id, now, user_id),
        )
    if old and old["name"] != name:
        log_audit("users", user_id, "name", old["name"], name, changed_by)


def count_active_admins(exclude_user_id: int = None) -> int:
    conn = get_connection()
    cur = conn.cursor()
    if exclude_user_id is not None:
        cur.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id != ?", (exclude_user_id,))
    else:
        cur.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1")
    count = cur.fetchone()[0]
    conn.close()
    return count


def set_worker_status(user_id: int, status: str, changed_by: int):
    """status: 'Active' | 'On Leave' | 'Inactive'. Active is the only
    status that can log in - On Leave and Inactive both block login
    (active=0), but stay visually distinct in Worker Management.
    Raises LastAdminError instead of applying the change if this would
    deactivate the only remaining active Admin account, which would lock
    everyone out of Admin functions permanently."""
    if status != "Active":
        with db_write() as (conn, cur):
            cur.execute("SELECT role FROM users WHERE id = ?", (user_id,))
            target = cur.fetchone()
        if target and target["role"] == "admin" and count_active_admins(exclude_user_id=user_id) == 0:
            raise LastAdminError("Cannot deactivate the last remaining active Admin account.")

    with db_write() as (conn, cur):
        cur.execute("SELECT status FROM users WHERE id = ?", (user_id,))
        old = cur.fetchone()
        now = datetime.now().isoformat(timespec="seconds")
        active = 1 if status == "Active" else 0
        cur.execute(
            "UPDATE users SET status = ?, active = ?, updated_at = ? WHERE id = ?",
            (status, active, now, user_id),
        )
    if old and old["status"] != status:
        log_audit("users", user_id, "status", old["status"], status, changed_by)


def admin_reset_pin(user_id: int, new_pin: str, changed_by: int, require_change: bool = True):
    """Admin resets someone's PIN (e.g. for a shift-cover worker or a
    forgotten PIN). require_change=True forces a change prompt at next
    login, so a temporary PIN can't stay in permanent use unnoticed."""
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "UPDATE users SET pin_hash = ?, must_change_pin = ?, updated_at = ? WHERE id = ?",
            (hash_pin(new_pin), 1 if require_change else 0, now, user_id),
        )
    log_audit("users", user_id, "pin_hash", "(hidden)", "(reset by admin)", changed_by)


def change_own_pin(user_id: int, current_pin: str, new_pin: str) -> bool:
    """Worker/Admin changes their own PIN. Returns False if current_pin is
    wrong (and nothing is changed); True on success."""
    user = verify_login(user_id, current_pin)
    if user is None:
        return False
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "UPDATE users SET pin_hash = ?, must_change_pin = 0, updated_at = ? WHERE id = ?",
            (hash_pin(new_pin), now, user_id),
        )
    log_audit("users", user_id, "pin_hash", "(hidden)", "(changed by self)", user_id)
    return True


# ---- Service / rate management (Admin only) ----

def get_all_services_admin():
    """Every service regardless of active status, for the management screen."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM services ORDER BY id")
    rows = cur.fetchall()
    conn.close()
    return rows


def create_service(name: str, rate: float, changed_by: int):
    """Raises DuplicateNameError (never a raw sqlite3 error) if a service
    with this name already exists, checked case-insensitively and after
    trimming whitespace, so 'xerox' and ' Xerox ' both collide with
    'Xerox'. This check happens BEFORE the insert is attempted, so a
    duplicate never even reaches the point where the UNIQUE constraint
    would fire - and the safe db_write() wrapper below guarantees the
    connection is closed either way, so a rejected duplicate can never
    leave a lock behind for the next operation."""
    name = name.strip()
    with db_write() as (conn, cur):
        cur.execute("SELECT id FROM services WHERE LOWER(TRIM(name)) = LOWER(?)", (name,))
        if cur.fetchone() is not None:
            raise DuplicateNameError(f"A service named '{name}' already exists.")
        now = datetime.now().isoformat()
        cur.execute(
            "INSERT INTO services (name, rate, active, created_at, updated_at) VALUES (?, ?, 1, ?, ?)",
            (name, rate, now, now),
        )
        row_id = cur.lastrowid
    log_audit("services", row_id, "created", None, f"{name} @ Rs{rate}", changed_by)
    return row_id


def update_service_rate(service_id: int, new_rate: float, changed_by: int):
    """Existing transactions already stored their own rate at the time they
    were created, so changing a service's rate here never alters past
    records - only future New Job entries will see the new price."""
    with db_write() as (conn, cur):
        cur.execute("SELECT name, rate FROM services WHERE id = ?", (service_id,))
        old = cur.fetchone()
        now = datetime.now().isoformat()
        cur.execute("UPDATE services SET rate = ?, updated_at = ? WHERE id = ?", (new_rate, now, service_id))
    if old and old["rate"] != new_rate:
        log_audit("services", service_id, "rate", old["rate"], new_rate, changed_by)


def set_service_active(service_id: int, active: bool, changed_by: int):
    with db_write() as (conn, cur):
        cur.execute("SELECT name, active FROM services WHERE id = ?", (service_id,))
        old = cur.fetchone()
        now = datetime.now().isoformat()
        cur.execute("UPDATE services SET active = ?, updated_at = ? WHERE id = ?", (1 if active else 0, now, service_id))
    if old and bool(old["active"]) != active:
        log_audit("services", service_id, "active", bool(old["active"]), active, changed_by)


# ---- Audit log viewer (Admin only) ----

def get_audit_logs(table_name: str = None, limit: int = 200):
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT al.*, u.name AS changed_by_name
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.changed_by
        WHERE 1=1
    """
    params = []
    if table_name:
        query += " AND al.table_name = ?"
        params.append(table_name)
    query += " ORDER BY al.id DESC LIMIT ?"
    params.append(limit)
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


# ---- Activity usage totals (for the redesigned Activity screen) ----

def get_today_app_usage_totals(worker_id: int = None):
    """Total time spent per application today, longest first - powers
    'TODAY'S APPLICATION USAGE'. Only counts activity that has actually
    ended (has a duration); the one currently open app is tracked live in
    memory by the monitor itself, not from this historical query."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT app_name, SUM(duration_seconds) AS total_seconds
        FROM application_activity
        WHERE date(start_time) = date('now', 'localtime') AND duration_seconds IS NOT NULL
    """
    params = []
    if worker_id is not None:
        query += " AND worker_id = ?"
        params.append(worker_id)
    query += " GROUP BY app_name ORDER BY total_seconds DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


# =====================================================================
# v5 — Enquiries (Part 12)
# =====================================================================

def create_enquiry(title: str, category: str, description: str, priority: str, created_by: int):
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO enquiries (title, category, description, priority, status, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 'Open', ?, ?, ?)",
            (title.strip(), category, description, priority, created_by, now, now),
        )
        row_id = cur.lastrowid
    log_audit("enquiries", row_id, "created", None, title.strip(), created_by)
    return row_id


def get_enquiries(created_by: int = None, status: str = None):
    """Pass created_by to scope to one worker's own enquiries; leave None
    for Admin's full view."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT e.*, u.name AS created_by_name, a.name AS assigned_to_name
        FROM enquiries e
        JOIN users u ON u.id = e.created_by
        LEFT JOIN users a ON a.id = e.assigned_to
        WHERE 1=1
    """
    params = []
    if created_by is not None:
        query += " AND e.created_by = ?"
        params.append(created_by)
    if status is not None and status != "All":
        query += " AND e.status = ?"
        params.append(status)
    query += " ORDER BY CASE e.priority WHEN 'Urgent' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, e.created_at DESC"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_enquiry_comments(enquiry_id: int):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.*, u.name AS created_by_name
        FROM enquiry_comments c
        JOIN users u ON u.id = c.created_by
        WHERE c.enquiry_id = ?
        ORDER BY c.created_at
    """, (enquiry_id,))
    rows = cur.fetchall()
    conn.close()
    return rows


def add_enquiry_comment(enquiry_id: int, comment: str, created_by: int):
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO enquiry_comments (enquiry_id, comment, created_by, created_at) VALUES (?, ?, ?, ?)",
            (enquiry_id, comment, created_by, now),
        )


def update_enquiry_status(enquiry_id: int, status: str, changed_by: int):
    with db_write() as (conn, cur):
        cur.execute("SELECT status FROM enquiries WHERE id = ?", (enquiry_id,))
        old = cur.fetchone()
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute("UPDATE enquiries SET status = ?, updated_at = ? WHERE id = ?", (status, now, enquiry_id))
    if old and old["status"] != status:
        log_audit("enquiries", enquiry_id, "status", old["status"], status, changed_by)


def assign_enquiry(enquiry_id: int, assigned_to: int, changed_by: int):
    with db_write() as (conn, cur):
        now = datetime.now().isoformat(timespec="seconds")
        cur.execute("UPDATE enquiries SET assigned_to = ?, updated_at = ? WHERE id = ?", (assigned_to, now, enquiry_id))
    log_audit("enquiries", enquiry_id, "assigned_to", None, assigned_to, changed_by)


# =====================================================================
# v5 — To-Do (Part 13)
# =====================================================================

def create_todo(title: str, description: str, priority: str, due_date: str,
                 created_by: int, assigned_to: int = None):
    now = datetime.now().isoformat(timespec="seconds")
    with db_write() as (conn, cur):
        cur.execute(
            "INSERT INTO todos (title, description, priority, status, due_date, created_by, assigned_to, created_at, updated_at) "
            "VALUES (?, ?, ?, 'Pending', ?, ?, ?, ?, ?)",
            (title.strip(), description, priority, due_date, created_by, assigned_to, now, now),
        )
        row_id = cur.lastrowid
    log_audit("todos", row_id, "created", None, title.strip(), created_by)
    return row_id


def get_todos(assigned_to: int = None, status: str = None):
    """Pass assigned_to to scope to one worker's own tasks; leave None for
    Admin's full view. A task with no assignee is a general owner task and
    is only shown in the Admin (unscoped) view."""
    conn = get_connection()
    cur = conn.cursor()
    query = """
        SELECT t.*, c.name AS created_by_name, a.name AS assigned_to_name
        FROM todos t
        JOIN users c ON c.id = t.created_by
        LEFT JOIN users a ON a.id = t.assigned_to
        WHERE 1=1
    """
    params = []
    if assigned_to is not None:
        query += " AND t.assigned_to = ?"
        params.append(assigned_to)
    if status is not None and status != "All":
        query += " AND t.status = ?"
        params.append(status)
    query += " ORDER BY CASE t.priority WHEN 'Urgent' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END, t.due_date IS NULL, t.due_date"
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return rows


def update_todo_status(todo_id: int, status: str, changed_by: int):
    with db_write() as (conn, cur):
        cur.execute("SELECT status FROM todos WHERE id = ?", (todo_id,))
        old = cur.fetchone()
        now = datetime.now().isoformat(timespec="seconds")
        completed_at = now if status == "Completed" else None
        cur.execute(
            "UPDATE todos SET status = ?, updated_at = ?, completed_at = ? WHERE id = ?",
            (status, now, completed_at, todo_id),
        )
    if old and old["status"] != status:
        log_audit("todos", todo_id, "status", old["status"], status, changed_by)


def get_todo_dashboard_counts():
    """Powers the Admin dashboard's 'TO-DO: N Pending, N Due Today, N Overdue'."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM todos WHERE status IN ('Pending', 'In Progress')")
    pending = cur.fetchone()[0]
    cur.execute("""
        SELECT COUNT(*) FROM todos
        WHERE status IN ('Pending', 'In Progress') AND due_date = date('now', 'localtime')
    """)
    due_today = cur.fetchone()[0]
    cur.execute("""
        SELECT COUNT(*) FROM todos
        WHERE status IN ('Pending', 'In Progress') AND due_date IS NOT NULL AND due_date < date('now', 'localtime')
    """)
    overdue = cur.fetchone()[0]
    conn.close()
    return {"pending": pending, "due_today": due_today, "overdue": overdue}


# =====================================================================
# v5 — Possible Missed Entry (Part 11)
# =====================================================================

def get_possible_missed_entries(worker_id: int = None, min_duration_seconds: int = 300):
    """
    A lightweight, honest heuristic - NOT proof of anything. Flags an
    activity interval as worth a look if:
      - it lasted at least min_duration_seconds (default 5 minutes) - a
        quick 20-second glance at an app isn't worth flagging
      - it wasn't "Test Event (synthetic)" (the diagnostic test button)
      - the worker has NO transaction recorded within 20 minutes after
        that activity ended (a generous window, since writing up a job
        after finishing the work is completely normal)
    This never says a job was missed - only that the activity pattern
    might be worth a look, exactly as Part 11 asks for.
    """
    conn = get_connection()
    cur = conn.cursor()
    w = " AND aa.worker_id = ?" if worker_id is not None else ""
    p = (worker_id,) if worker_id is not None else ()
    cur.execute(f"""
        SELECT aa.*, u.name AS worker_name
        FROM application_activity aa
        JOIN users u ON u.id = aa.worker_id
        WHERE date(aa.start_time) = date('now', 'localtime')
          AND aa.duration_seconds IS NOT NULL
          AND aa.duration_seconds >= ?
          AND aa.app_name != 'Test Event (synthetic)'
          AND NOT EXISTS (
              SELECT 1 FROM transactions t
              WHERE t.worker_id = aa.worker_id
                AND datetime(t.created_at) BETWEEN datetime(aa.end_time) AND datetime(aa.end_time, '+20 minutes')
          )
          {w}
        ORDER BY aa.start_time DESC
    """, (min_duration_seconds, *p))
    rows = cur.fetchall()
    conn.close()
    return rows
