"""统计分析准入服务的 SQLite 模式与事务辅助。"""

from __future__ import annotations

import contextlib
import sqlite3
from collections.abc import Iterator
from pathlib import Path


SCHEMA_VERSION = 3

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS protocol_catalog (
    protocol_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    title TEXT NOT NULL,
    task_family TEXT NOT NULL,
    canonical_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    PRIMARY KEY (protocol_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('operator', 'statistician', 'approver', 'auditor', 'compliance')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
);

CREATE TABLE IF NOT EXISTS cooperation_programs (
    program_id TEXT PRIMARY KEY,
    program_name TEXT NOT NULL,
    lead_organization TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence_revisions (
    evidence_revision_id TEXT PRIMARY KEY,
    program_id TEXT NOT NULL REFERENCES cooperation_programs(program_id),
    version TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    created_at TEXT NOT NULL,
    UNIQUE (program_id, version),
    UNIQUE (content_sha256)
);

CREATE TABLE IF NOT EXISTS batches (
    batch_id TEXT PRIMARY KEY,
    protocol_id TEXT NOT NULL,
    protocol_version INTEGER NOT NULL,
    evidence_revision_id TEXT NOT NULL REFERENCES evidence_revisions(evidence_revision_id),
    state TEXT NOT NULL CHECK (state IN ('draft', 'running', 'sealed', 'analyzing', 'analyzed', 'decided')),
    revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0),
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    started_at TEXT,
    sealed_at TEXT,
    FOREIGN KEY (protocol_id, protocol_version) REFERENCES protocol_catalog(protocol_id, version)
);

CREATE TABLE IF NOT EXISTS observations (
    observation_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    source_batch TEXT NOT NULL,
    source_row TEXT NOT NULL,
    program_id TEXT NOT NULL REFERENCES cooperation_programs(program_id),
    stratum_key TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    content_sha256 TEXT NOT NULL CHECK (length(content_sha256) = 64),
    imported_by TEXT NOT NULL REFERENCES users(user_id),
    imported_at TEXT NOT NULL,
    UNIQUE (batch_id, source_batch, source_row)
);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, key)
);

CREATE TABLE IF NOT EXISTS exclusion_requests (
    exclusion_id INTEGER PRIMARY KEY AUTOINCREMENT,
    observation_id INTEGER NOT NULL REFERENCES observations(observation_id),
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'revoked')),
    reason TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(user_id),
    requested_at TEXT NOT NULL,
    reviewed_by TEXT REFERENCES users(user_id),
    reviewed_at TEXT,
    review_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS one_open_exclusion_per_observation
ON exclusion_requests(observation_id)
WHERE status IN ('pending', 'approved');

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'succeeded', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    available_at TEXT NOT NULL,
    lease_owner TEXT,
    lease_expires_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision)
);

CREATE TABLE IF NOT EXISTS analyses (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    batch_revision INTEGER NOT NULL,
    protocol_sha256 TEXT NOT NULL CHECK (length(protocol_sha256) = 64),
    input_sha256 TEXT NOT NULL CHECK (length(input_sha256) = 64),
    algorithm_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (batch_id, batch_revision, input_sha256)
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision TEXT NOT NULL CHECK (decision IN ('needs_more_data', 'approved', 'rejected')),
    reason TEXT NOT NULL,
    decided_by TEXT NOT NULL REFERENCES users(user_id),
    decided_at TEXT NOT NULL,
    UNIQUE (batch_id, analysis_id)
);

CREATE TABLE IF NOT EXISTS audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- 分级披露：封签密钥支持轮换；旧披露包继续可用旧密钥验签。
CREATE TABLE IF NOT EXISTS sealing_keys (
    key_id TEXT PRIMARY KEY,
    secret_b64 TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    created_at TEXT NOT NULL,
    retired_at TEXT
);

-- 分级披露：由责任方选择版本、目的、接收主体、允许声明、遮蔽规则和期限后冻结。
CREATE TABLE IF NOT EXISTS disclosure_packages (
    package_id TEXT PRIMARY KEY,
    batch_id TEXT NOT NULL REFERENCES batches(batch_id),
    analysis_id INTEGER NOT NULL REFERENCES analyses(analysis_id),
    decision_id INTEGER REFERENCES decisions(decision_id),
    purpose_code TEXT NOT NULL,
    purpose_detail TEXT NOT NULL,
    recipient_class TEXT NOT NULL CHECK (recipient_class IN ('foreign_investor', 'local_regulator', 'independent_assessor')),
    recipients_json TEXT NOT NULL,
    allowed_statements_json TEXT NOT NULL,
    field_policy_json TEXT NOT NULL,
    jurisdictions_allowed_json TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    retain_until TEXT NOT NULL,
    scope_fingerprint TEXT NOT NULL CHECK (length(scope_fingerprint) = 64),
    package_sha256 TEXT NOT NULL CHECK (length(package_sha256) = 64),
    envelope_json TEXT NOT NULL,
    sign_key_id TEXT NOT NULL,
    sign_key_seq INTEGER NOT NULL DEFAULT 1 CHECK (sign_key_seq > 0),
    signature TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
    superseded_by TEXT REFERENCES disclosure_packages(package_id),
    revocation_reason TEXT,
    revoked_by TEXT REFERENCES users(user_id),
    revoked_at TEXT,
    created_by TEXT NOT NULL REFERENCES users(user_id),
    created_at TEXT NOT NULL,
    UNIQUE (package_sha256)
);

CREATE INDEX IF NOT EXISTS idx_disclosure_packages_batch ON disclosure_packages(batch_id);

-- 分级披露：每个接收主体一个不透明投递令牌（仅存其 SHA-256）；令牌只用于读披露包。
CREATE TABLE IF NOT EXISTS disclosure_recipients (
    package_id TEXT NOT NULL REFERENCES disclosure_packages(package_id),
    recipient_id TEXT NOT NULL,
    name TEXT NOT NULL,
    jurisdiction TEXT NOT NULL,
    token_sha256 TEXT NOT NULL CHECK (length(token_sha256) = 64),
    PRIMARY KEY (package_id, recipient_id)
);

-- 分级披露：读取尝试（含被拒绝）与交付事实永久保留，不随撤回删除。
CREATE TABLE IF NOT EXISTS disclosure_accesses (
    access_id INTEGER PRIMARY KEY AUTOINCREMENT,
    package_id TEXT NOT NULL REFERENCES disclosure_packages(package_id),
    attempt_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    recipient_id TEXT,
    jurisdiction TEXT,
    decision TEXT NOT NULL CHECK (decision IN ('delivered', 'denied')),
    deny_reason TEXT,
    fields_seen_json TEXT,
    digest_sha256 TEXT,
    attempted_at TEXT NOT NULL,
    UNIQUE (package_id, attempt_id)
);

CREATE INDEX IF NOT EXISTS idx_disclosure_accesses_package ON disclosure_accesses(package_id, access_id);
"""

REQUIRED_TABLES = frozenset({
    "schema_meta", "protocol_catalog", "users", "cooperation_programs", "evidence_revisions", "batches",
    "observations", "idempotency_keys", "exclusion_requests", "analysis_jobs",
    "analyses", "decisions", "audit_events",
    "sealing_keys", "disclosure_packages", "disclosure_recipients", "disclosure_accesses",
})


def connect(path: str | Path) -> sqlite3.Connection:
    """打开连接并启用严格的事务与外键设置。"""

    connection = sqlite3.connect(str(path), isolation_level=None)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextlib.contextmanager
def transaction(connection: sqlite3.Connection, *, immediate: bool = False) -> Iterator[None]:
    """显式事务；异常时保证回滚。"""

    connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
    try:
        yield
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def initialize(connection: sqlite3.Connection) -> None:
    """初始化基础资料表，重复执行不改变已有数据。"""

    connection.executescript(SCHEMA_SQL)
    with transaction(connection, immediate=True):
        connection.execute(
            "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(SCHEMA_VERSION),),
        )


def inspect_schema(connection: sqlite3.Connection) -> dict[str, object]:
    """返回适合机器检查的数据库结构摘要。"""

    table_rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    tables = tuple(row["name"] for row in table_rows)
    version_row = connection.execute(
        "SELECT value FROM schema_meta WHERE key='schema_version'"
    ).fetchone()
    missing = sorted(REQUIRED_TABLES - set(tables))
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
    return {
        "tables": tables,
        "missing_tables": missing,
        "schema_version": None if version_row is None else version_row["value"],
        "foreign_keys": bool(foreign_keys),
    }
