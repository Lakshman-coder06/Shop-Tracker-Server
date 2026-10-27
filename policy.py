"""
policy.py
----------
THE SECURITY RULES. Every request an app sends to the server is checked
against this table BEFORE it reaches the database.

Why this exists: in the old single-PC app, "a Worker only sees their own
jobs" was enforced by the SCREEN (it passed worker_id=<me> to the
database). Once data lives on a shared server, that is not enough - anyone
who can reach the server could send worker_id=None and read everyone's
sales. So the server enforces the rules itself and ignores what the app
claims about who is asking.

Each function the app may call has a Rule:

  roles    who may call it at all. None = any logged-in user.
  force    parameters that are ALWAYS overwritten with the caller's own id
           (e.g. worker_id / changed_by / recorded_by), so nobody can
           record a sale or an audit-log entry under someone else's name.
  scope    parameters overwritten with the caller's id ONLY when the
           caller is a plain Worker (Admin/Supervisor keep whatever they
           asked for, e.g. None = "everyone"). This is the "workers only
           see their own data" rule.
  owner    (table, id_column, param, owner_column, who) - the record being
           touched must belong to the caller. who="worker": only Workers
           are checked (Admin may touch anyone's); who="all": everyone is.
  check    extra validation of the arguments (positive amounts, valid
           payment methods, ...). Raises PolicyError with a clear message.
  clamp    {param: (min, max)} - keeps "limit" style numbers sane.

Functions NOT listed here cannot be called over the network at all
(e.g. the legacy mark_transaction_paid, the internal log_audit helper).
"""

import shop_db


class PolicyError(Exception):
    """The caller is logged in but not allowed to do this (HTTP 403)."""


class BadRequestError(Exception):
    """The request itself is malformed or invalid (HTTP 400)."""


PAYMENT_METHODS = {"Cash", "UPI"}
JOB_STATUSES = {"Completed", "Pending", "In Progress"}
ROLES = {"worker", "supervisor", "admin"}
WORKER_STATUSES = {"Active", "On Leave", "Inactive"}
ENQUIRY_STATUSES = {"Open", "In Progress", "Resolved", "Closed"}
TODO_STATUSES = {"Pending", "In Progress", "Completed", "Cancelled"}
PRIORITIES = {"Low", "Medium", "High", "Urgent"}
MAX_MONEY = 1_000_000  # same ceiling the app's own input boxes use


# ---------------------------------------------------------------------
# small validation helpers
# ---------------------------------------------------------------------

def _num(params, name, minimum=None, maximum=None, allow_none=False):
    v = params.get(name)
    if v is None and allow_none:
        return
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise BadRequestError(f"'{name}' must be a number.")
    if minimum is not None and v < minimum:
        raise BadRequestError(f"'{name}' must be at least {minimum}.")
    if maximum is not None and v > maximum:
        raise BadRequestError(f"'{name}' must be at most {maximum}.")


def _one_of(params, name, allowed, allow_none=False):
    v = params.get(name)
    if v is None and allow_none:
        return
    if v not in allowed:
        raise BadRequestError(f"'{name}' must be one of: {', '.join(sorted(allowed))}.")


def _pin(params, name):
    v = params.get(name)
    if not isinstance(v, str) or not (4 <= len(v) <= 8):
        raise BadRequestError("A PIN must be 4 to 8 characters long.")


def _check_create_transaction(p):
    _num(p, "quantity", 1, 9999)
    _num(p, "advance_amount", 0, MAX_MONEY, allow_none=True)
    _one_of(p, "payment_method", PAYMENT_METHODS)
    _one_of(p, "status", JOB_STATUSES)


def _check_record_payment(p):
    _num(p, "amount", 0.01, MAX_MONEY)
    _one_of(p, "payment_method", PAYMENT_METHODS)


def _check_create_expense(p):
    _num(p, "amount", 0.01, MAX_MONEY)
    _one_of(p, "payment_method", PAYMENT_METHODS)


def _name_taken(name, exclude_id=None):
    """True if another account already uses this name (ignoring capitals and
    spaces - the same way login matches names). The old single-PC app never
    checked this, so two 'Worker 1' accounts were possible and the second
    could never log in."""
    conn = shop_db.get_connection()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE LOWER(TRIM(name)) = LOWER(?) AND id != ?",
            ((name or "").strip(), -1 if exclude_id is None else exclude_id),
        ).fetchone()
    finally:
        conn.close()
    return row is not None


def _check_create_worker(p):
    _pin(p, "pin")
    _one_of(p, "role", ROLES)
    if not (p.get("name") or "").strip():
        raise BadRequestError("Name is required.")
    if _name_taken(p["name"]):
        raise BadRequestError(f"Someone named '{p['name'].strip()}' already exists. Please choose a different name.")


def _check_update_worker(p):
    if not (p.get("name") or "").strip():
        raise BadRequestError("Name is required.")
    if _name_taken(p["name"], p.get("user_id")):
        raise BadRequestError(f"Someone named '{p['name'].strip()}' already exists. Please choose a different name.")


def _check_reset_pin(p):
    _pin(p, "new_pin")


def _check_change_pin(p):
    _pin(p, "new_pin")


def _check_set_status(p):
    _one_of(p, "status", WORKER_STATUSES)


def _check_rate(p):
    _num(p, "rate", 0, MAX_MONEY)


def _check_new_rate(p):
    _num(p, "new_rate", 0, MAX_MONEY)


def _check_closing(p):
    for n in ("opening_cash", "expected_cash", "actual_cash", "difference"):
        _num(p, n, -MAX_MONEY * 10, MAX_MONEY * 10)


def _check_enquiry_status(p):
    _one_of(p, "status", ENQUIRY_STATUSES)


def _check_todo_status(p):
    _one_of(p, "status", TODO_STATUSES)


def _check_create_todo(p):
    _one_of(p, "priority", PRIORITIES)
    if not (p.get("title") or "").strip():
        raise BadRequestError("Title is required.")


def _check_create_enquiry(p):
    _one_of(p, "priority", PRIORITIES)
    if not (p.get("title") or "").strip():
        raise BadRequestError("Title is required.")


# ---------------------------------------------------------------------
# The Rule object + the table
# ---------------------------------------------------------------------

class Rule:
    def __init__(self, roles=None, force=(), scope=(), owner=None, check=None, clamp=None):
        self.roles = set(roles) if roles else None
        self.force = tuple(force)
        self.scope = tuple(scope)
        self.owner = owner
        self.check = check
        self.clamp = clamp or {}


ADMIN = {"admin"}

POLICY = {
    # ---- Reference data any logged-in user needs ----
    "get_active_workers": Rule(),
    "get_active_services": Rule(),
    "get_user_by_id": Rule(scope=("user_id",)),
    "change_own_pin": Rule(force=("user_id",), check=_check_change_pin),
    "check_db_connection": Rule(),
    "get_last_activity_saved": Rule(),

    # ---- Dashboard / totals ----
    "get_today_summary": Rule(scope=("worker_id",)),
    "get_worker_performance_today": Rule(roles=ADMIN),
    "get_today_transaction_totals": Rule(roles=ADMIN),
    "get_todo_dashboard_counts": Rule(),

    # ---- Login sessions + activity tracking (strictly your own) ----
    "start_worker_session": Rule(force=("worker_id",)),
    "end_worker_session": Rule(owner=("worker_sessions", "id", "session_id", "worker_id", "all")),
    "log_activity_start": Rule(force=("worker_id",)),
    "log_activity_end": Rule(owner=("application_activity", "id", "row_id", "worker_id", "all")),
    "get_recent_activity": Rule(scope=("worker_id",), clamp={"limit": (1, 500)}),
    "get_activity_history": Rule(scope=("worker_id",)),
    "get_activity_by_id": Rule(owner=("application_activity", "id", "activity_id", "worker_id", "worker")),
    "get_distinct_activity_apps": Rule(),
    "get_today_app_usage_totals": Rule(scope=("worker_id",)),
    "get_possible_missed_entries": Rule(scope=("worker_id",)),

    # ---- Jobs / payments ----
    "create_transaction": Rule(force=("worker_id",), check=_check_create_transaction),
    "get_transactions": Rule(scope=("worker_id",)),
    "get_pending_transactions": Rule(scope=("worker_id",)),
    "get_transaction_payments": Rule(owner=("transactions", "id", "transaction_id", "worker_id", "worker")),
    "record_payment": Rule(force=("recorded_by",), check=_check_record_payment,
                           owner=("transactions", "id", "transaction_id", "worker_id", "worker")),
    "mark_transaction_completed": Rule(force=("changed_by",),
                                       owner=("transactions", "id", "transaction_id", "worker_id", "worker")),
    "mark_transaction_in_progress": Rule(force=("changed_by",),
                                         owner=("transactions", "id", "transaction_id", "worker_id", "worker")),
    "cancel_transaction": Rule(force=("changed_by",),
                               owner=("transactions", "id", "transaction_id", "worker_id", "worker")),

    # ---- Expenses ----
    "create_expense": Rule(force=("worker_id",), check=_check_create_expense),
    "get_expenses_today": Rule(scope=("worker_id",)),

    # ---- Daily closing ----
    "get_daily_totals_for_closing": Rule(),
    "get_daily_closing": Rule(),
    "save_daily_closing": Rule(force=("closed_by",), check=_check_closing),

    # ---- Admin: workers ----
    "get_all_workers_admin": Rule(roles=ADMIN),
    "create_worker": Rule(roles=ADMIN, check=_check_create_worker),
    "update_worker": Rule(roles=ADMIN, force=("changed_by",), check=_check_update_worker),
    "set_worker_status": Rule(roles=ADMIN, force=("changed_by",), check=_check_set_status),
    "admin_reset_pin": Rule(roles=ADMIN, force=("changed_by",), check=_check_reset_pin),

    # ---- Admin: services / rates ----
    "get_all_services_admin": Rule(roles=ADMIN),
    "create_service": Rule(roles=ADMIN, force=("changed_by",), check=_check_rate),
    "update_service_rate": Rule(roles=ADMIN, force=("changed_by",), check=_check_new_rate),
    "set_service_active": Rule(roles=ADMIN, force=("changed_by",)),

    # ---- Admin: audit log ----
    "get_audit_logs": Rule(roles=ADMIN, clamp={"limit": (1, 1000)}),

    # ---- Enquiries ----
    "create_enquiry": Rule(force=("created_by",), check=_check_create_enquiry),
    "get_enquiries": Rule(scope=("created_by",)),
    "get_enquiry_comments": Rule(owner=("enquiries", "id", "enquiry_id", "created_by", "worker")),
    "add_enquiry_comment": Rule(roles=ADMIN, force=("created_by",)),
    "update_enquiry_status": Rule(roles=ADMIN, force=("changed_by",), check=_check_enquiry_status),
    "assign_enquiry": Rule(roles=ADMIN, force=("changed_by",)),

    # ---- To-Do ----
    "create_todo": Rule(roles=ADMIN, force=("created_by",), check=_check_create_todo),
    "get_todos": Rule(scope=("assigned_to",)),
    "update_todo_status": Rule(force=("changed_by",), check=_check_todo_status,
                               owner=("todos", "id", "todo_id", "assigned_to", "worker")),
}


# ---------------------------------------------------------------------
# applying a rule
# ---------------------------------------------------------------------

def _record_owner(table, id_col, owner_col, record_id):
    """Looks up who owns a record. Table/column names come from the
    static table above, never from the request."""
    conn = shop_db.get_connection()
    try:
        row = conn.execute(
            f"SELECT {owner_col} FROM {table} WHERE {id_col} = ?", (record_id,)
        ).fetchone()
    finally:
        conn.close()
    return None if row is None else row[0]


def apply_rule(fn_name, user, params):
    """
    user:   dict with at least id and role (read fresh from the database
            for every request, so a deactivated account or changed role
            takes effect immediately).
    params: dict of the function's arguments (already bound by name).
    Returns the (possibly rewritten) params, or raises PolicyError /
    BadRequestError.
    """
    rule = POLICY[fn_name]
    uid = user["id"]
    role = user["role"]
    is_worker = role == "worker"

    if rule.roles is not None and role not in rule.roles:
        raise PolicyError("You do not have permission to do that.")

    # Identity stamping: always the real caller, never what the app claims.
    for name in rule.force:
        if name in params:
            params[name] = uid

    # Workers are confined to their own data.
    if is_worker:
        for name in rule.scope:
            if name in params:
                params[name] = uid

    # Record ownership.
    if rule.owner is not None:
        table, id_col, param, owner_col, who = rule.owner
        if who == "all" or is_worker:
            owner_id = _record_owner(table, id_col, owner_col, params.get(param))
            if owner_id is not None and owner_id != uid:
                raise PolicyError("That record belongs to someone else.")

    if rule.check is not None:
        rule.check(params)

    for name, (lo, hi) in rule.clamp.items():
        if name in params and isinstance(params[name], (int, float)):
            params[name] = max(lo, min(hi, params[name]))

    return params
