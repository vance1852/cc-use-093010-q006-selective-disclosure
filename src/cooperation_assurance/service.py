"""统计分析准入服务的领域用例。"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import timedelta
from decimal import Decimal
from typing import Any, Iterable, Mapping

from . import disclosure
from .analysis import ALGORITHM_VERSION, analyze
from .clock import SystemClock, isoformat
from .contracts import Observation, Protocol, ValidationError
from .errors import Conflict, DisclosureDenied, Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json, content_digest
from .storage import initialize, transaction


ROLE_PERMISSIONS = {
    "operator": {
        "catalog.write", "batch.create", "batch.start", "observation.import",
        "exclusion.request", "exclusion.revoke",
    },
    "statistician": {"protocol.publish", "batch.seal", "exclusion.review", "analysis.run"},
    "approver": {
        "decision.write",
        "disclosure.issue", "disclosure.revoke", "disclosure.resign", "disclosure.admin",
    },
    "auditor": {"report.read", "audit.read", "disclosure.ledger"},
}


class AssuranceService:
    """在单个 SQLite 连接上提供全部业务操作。"""

    def __init__(self, connection: sqlite3.Connection, clock=None) -> None:
        self.connection = connection
        self.clock = clock or SystemClock()
        initialize(connection)

    def _now(self) -> str:
        return isoformat(self.clock.now())

    def _user(self, user_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT user_id, display_name, role, active FROM users WHERE user_id=?", (user_id,)
        ).fetchone()
        if row is None:
            raise NotFound(f"用户不存在: {user_id}")
        if not row["active"]:
            raise Forbidden("用户已停用")
        return row

    def _require(self, user_id: str, permission: str) -> sqlite3.Row:
        user = self._user(user_id)
        if permission not in ROLE_PERMISSIONS[user["role"]]:
            raise Forbidden(f"角色 {user['role']} 无权执行 {permission}")
        return user

    def _audit(
        self, entity_type: str, entity_id: str, event_type: str, actor_id: str, payload: Mapping[str, Any]
    ) -> None:
        self.connection.execute(
            "INSERT INTO audit_events(entity_type,entity_id,event_type,actor_id,payload_json,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (entity_type, entity_id, event_type, actor_id, canonical_json(payload), self._now()),
        )

    def create_user(self, user_id: str, display_name: str, role: str) -> dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValidationFailed(f"未知角色: {role}")
        if not user_id.strip() or not display_name.strip():
            raise ValidationFailed("用户编号和名称不能为空")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO users(user_id,display_name,role) VALUES(?,?,?)",
                    (user_id.strip(), display_name.strip(), role),
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"用户已存在: {user_id}") from exc
        return {"user_id": user_id.strip(), "role": role}

    def register_program(
        self, actor_id: str, program_id: str, program_name: str, lead_organization: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO cooperation_programs(program_id,program_name,lead_organization,created_at) VALUES(?,?,?,?)",
                    (program_id, program_name, lead_organization, self._now()),
                )
                self._audit("asset", program_id, "asset.registered", actor_id, {"program_name": program_name})
        except sqlite3.IntegrityError as exc:
            raise Conflict(f"跨境合作项目已存在: {program_id}") from exc
        return {"program_id": program_id, "program_name": program_name, "lead_organization": lead_organization}

    def register_evidence_revision(
        self, actor_id: str, evidence_revision_id: str, program_id: str, version: str, content_sha256: str
    ) -> dict[str, Any]:
        self._require(actor_id, "catalog.write")
        if len(content_sha256) != 64:
            raise ValidationFailed("证据版本摘要必须是 64 位 SHA-256")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO evidence_revisions(evidence_revision_id,program_id,version,content_sha256,created_at) VALUES(?,?,?,?,?)",
                    (evidence_revision_id, program_id, version, content_sha256.lower(), self._now()),
                )
                self._audit("evidence_revision", evidence_revision_id, "evidence_revision.registered", actor_id, {"program_id": program_id, "version": version})
        except sqlite3.IntegrityError as exc:
            raise Conflict("证据版本编号、版本或摘要冲突") from exc
        return {"evidence_revision_id": evidence_revision_id, "program_id": program_id, "version": version}

    def publish_protocol(self, actor_id: str, raw: Mapping[str, Any]) -> dict[str, Any]:
        self._require(actor_id, "protocol.publish")
        try:
            protocol = Protocol.from_dict(raw)
        except ValidationError as exc:
            raise ValidationFailed(str(exc)) from exc
        text = canonical_json(raw)
        digest = content_digest([raw])
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO protocol_catalog(protocol_id,version,title,task_family,canonical_json,content_sha256,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        protocol.protocol_id,
                        protocol.version,
                        protocol.title,
                        protocol.task_family,
                        text,
                        digest,
                        self._now(),
                    ),
                )
                identity = f"{protocol.protocol_id}@{protocol.version}"
                self._audit("protocol", identity, "protocol.published", actor_id, {"sha256": digest})
        except sqlite3.IntegrityError as exc:
            raise Conflict("协议版本或内容摘要已经存在") from exc
        return {"protocol_id": protocol.protocol_id, "version": protocol.version, "sha256": digest}

    def _protocol(self, protocol_id: str, version: int) -> tuple[Protocol, str]:
        row = self.connection.execute(
            "SELECT canonical_json,content_sha256 FROM protocol_catalog WHERE protocol_id=? AND version=?",
            (protocol_id, version),
        ).fetchone()
        if row is None:
            raise NotFound("协议版本不存在")
        return Protocol.from_dict(json.loads(row["canonical_json"])), row["content_sha256"]

    def create_batch(
        self,
        actor_id: str,
        batch_id: str,
        protocol_id: str,
        protocol_version: int,
        evidence_revision_id: str,
    ) -> dict[str, Any]:
        self._require(actor_id, "batch.create")
        self._protocol(protocol_id, protocol_version)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO batches(batch_id,protocol_id,protocol_version,evidence_revision_id,state,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (batch_id, protocol_id, protocol_version, evidence_revision_id, "draft", actor_id, self._now()),
                )
                self._audit("batch", batch_id, "batch.created", actor_id, {"evidence_revision_id": evidence_revision_id})
        except sqlite3.IntegrityError as exc:
            raise Conflict("批次编号冲突或证据版本不存在") from exc
        return self.get_batch(batch_id)

    def get_batch(self, batch_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM batches WHERE batch_id=?", (batch_id,)).fetchone()
        if row is None:
            raise NotFound("批次不存在")
        return dict(row)

    def start_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.start")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE batches SET state='running',revision=revision+1,started_at=? "
                "WHERE batch_id=? AND state='draft' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次不是当前草稿版本")
            self._audit("batch", batch_id, "batch.started", actor_id, {"from_revision": expected_revision})
        return self.get_batch(batch_id)

    def _idempotent_response(self, scope: str, key: str, request_digest: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT request_sha256,response_json FROM idempotency_keys WHERE scope=? AND key=?",
            (scope, key),
        ).fetchone()
        if row is None:
            return None
        if row["request_sha256"] != request_digest:
            raise Conflict("同一幂等键对应了不同请求内容")
        return json.loads(row["response_json"])

    def import_observations(
        self,
        actor_id: str,
        batch_id: str,
        idempotency_key: str,
        raw_rows: Iterable[Mapping[str, Any]],
    ) -> dict[str, Any]:
        self._require(actor_id, "observation.import")
        rows = tuple(raw_rows)
        if not rows:
            raise ValidationFailed("测点数组不能为空")
        request_digest = content_digest(rows)
        scope = f"observations:{batch_id}"
        existing = self._idempotent_response(scope, idempotency_key, request_digest)
        if existing is not None:
            return existing
        batch = self.get_batch(batch_id)
        if batch["state"] != "running":
            raise InvalidState("只有运行中的批次可以导入测点")
        protocol, _ = self._protocol(batch["protocol_id"], batch["protocol_version"])
        parsed: list[Observation] = []
        for raw in rows:
            try:
                item = Observation.from_dict(raw, protocol)
            except ValidationError as exc:
                raise ValidationFailed(str(exc)) from exc
            if item.program_id != self.connection.execute(
                "SELECT program_id FROM evidence_revisions WHERE evidence_revision_id=?", (batch["evidence_revision_id"],)
            ).fetchone()["program_id"]:
                raise ValidationFailed("测点跨境合作项目与批次证据版本不一致")
            parsed.append(item)
        response = {"batch_id": batch_id, "inserted": len(parsed), "request_sha256": request_digest}
        try:
            with transaction(self.connection, immediate=True):
                for item, raw in zip(parsed, rows):
                    self.connection.execute(
                        "INSERT INTO observations(batch_id,source_batch,source_row,program_id,stratum_key,observed_at," 
                        "metrics_json,content_sha256,imported_by,imported_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                        (
                            batch_id,
                            item.source_batch,
                            item.source_row,
                            item.program_id,
                            item.stratum_key,
                            item.observed_at,
                            canonical_json({key: format(value, "f") for key, value in item.metrics.items()}),
                            content_digest([raw]),
                            actor_id,
                            self._now(),
                        ),
                    )
                self.connection.execute(
                    "INSERT INTO idempotency_keys(scope,key,request_sha256,response_json,created_at) VALUES(?,?,?,?,?)",
                    (scope, idempotency_key, request_digest, canonical_json(response), self._now()),
                )
                self._audit("batch", batch_id, "observations.imported", actor_id, response)
        except sqlite3.IntegrityError as exc:
            raise Conflict("来源行重复或幂等键并发冲突") from exc
        return response

    def request_exclusion(self, actor_id: str, observation_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.request")
        observation = self.connection.execute(
            "SELECT observation_id,batch_id FROM observations WHERE observation_id=?", (observation_id,)
        ).fetchone()
        if observation is None:
            raise NotFound("测点不存在")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO exclusion_requests(observation_id,status,reason,requested_by,requested_at) "
                    "VALUES(?,?,?,?,?)",
                    (observation_id, "pending", reason, actor_id, self._now()),
                )
                exclusion_id = cursor.lastrowid
                self._audit("observation", str(observation_id), "exclusion.requested", actor_id, {"reason": reason})
        except sqlite3.IntegrityError as exc:
            raise Conflict("该测点已有待处理或生效排除") from exc
        return {"exclusion_id": exclusion_id, "status": "pending"}

    def review_exclusion(
        self, actor_id: str, exclusion_id: int, approve: bool, note: str
    ) -> dict[str, Any]:
        self._require(actor_id, "exclusion.review")
        row = self.connection.execute(
            "SELECT * FROM exclusion_requests WHERE exclusion_id=?", (exclusion_id,)
        ).fetchone()
        if row is None:
            raise NotFound("排除申请不存在")
        if row["status"] != "pending":
            raise InvalidState("排除申请已经处理")
        if row["requested_by"] == actor_id:
            raise Forbidden("申请人不能复核自己的排除申请")
        status = "approved" if approve else "rejected"
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE exclusion_requests SET status=?,reviewed_by=?,reviewed_at=?,review_note=? "
                "WHERE exclusion_id=? AND status='pending'",
                (status, actor_id, self._now(), note, exclusion_id),
            )
            self._audit("exclusion", str(exclusion_id), f"exclusion.{status}", actor_id, {"note": note})
        return {"exclusion_id": exclusion_id, "status": status}

    def revoke_exclusion(self, actor_id: str, exclusion_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "exclusion.revoke")
        row = self.connection.execute(
            "SELECT e.*,o.batch_id FROM exclusion_requests e "
            "JOIN observations o ON o.observation_id=e.observation_id WHERE e.exclusion_id=?",
            (exclusion_id,),
        ).fetchone()
        if row is None:
            raise NotFound("排除记录不存在")
        if row["status"] != "approved":
            raise InvalidState("只有已批准的排除可以撤销")
        if row["requested_by"] != actor_id:
            raise Forbidden("只有原申请人可以撤销排除")
        batch = self.get_batch(row["batch_id"])
        if batch["state"] != "running":
            raise InvalidState("批次封存后不能改变排除状态")
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE exclusion_requests SET status='revoked',review_note=?,reviewed_at=? "
                "WHERE exclusion_id=? AND status='approved'",
                (reason, self._now(), exclusion_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("排除状态已变化")
            self._audit(
                "observation",
                str(row["observation_id"]),
                "exclusion.revoked",
                actor_id,
                {"exclusion_id": exclusion_id, "reason": reason},
            )
        return {"exclusion_id": exclusion_id, "status": "revoked"}

    def seal_batch(self, actor_id: str, batch_id: str, expected_revision: int) -> dict[str, Any]:
        self._require(actor_id, "batch.seal")
        with transaction(self.connection, immediate=True):
            pending = self.connection.execute(
                "SELECT count(*) FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
                "WHERE o.batch_id=? AND e.status='pending'", (batch_id,)
            ).fetchone()[0]
            if pending:
                raise InvalidState("仍有待复核的排除申请")
            cursor = self.connection.execute(
                "UPDATE batches SET state='sealed',revision=revision+1,sealed_at=? "
                "WHERE batch_id=? AND state='running' AND revision=?",
                (self._now(), batch_id, expected_revision),
            )
            if cursor.rowcount != 1:
                raise InvalidState("批次状态或版本已变化")
            new_revision = expected_revision + 1
            now = self._now()
            self.connection.execute(
                "INSERT INTO analysis_jobs(batch_id,batch_revision,state,available_at,created_at,updated_at) "
                "VALUES(?,?, 'queued', ?,?,?)",
                (batch_id, new_revision, now, now, now),
            )
            self._audit("batch", batch_id, "batch.sealed", actor_id, {"revision": new_revision})
        return self.get_batch(batch_id)

    def claim_job(self, worker_id: str, lease_seconds: int = 60) -> dict[str, Any] | None:
        if lease_seconds <= 0:
            raise ValidationFailed("租约时长必须大于零")
        now = self._now()
        expires = isoformat(self.clock.now() + timedelta(seconds=lease_seconds))
        with transaction(self.connection, immediate=True):
            row = self.connection.execute(
                "SELECT job_id FROM analysis_jobs WHERE "
                "(state='queued' AND available_at<=?) OR (state='leased' AND lease_expires_at<=?) "
                "ORDER BY available_at,job_id LIMIT 1",
                (now, now),
            ).fetchone()
            if row is None:
                return None
            self.connection.execute(
                "UPDATE analysis_jobs SET state='leased',attempts=attempts+1,lease_owner=?,lease_expires_at=?,updated_at=? "
                "WHERE job_id=?",
                (worker_id, expires, now, row["job_id"]),
            )
            claimed = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (row["job_id"],)).fetchone()
        return dict(claimed)

    def _analysis_observations(self, batch_id: str, protocol: Protocol) -> tuple[Observation, ...]:
        rows = self.connection.execute(
            "SELECT o.*,e.reason AS excluded_reason FROM observations o "
            "LEFT JOIN exclusion_requests e ON e.observation_id=o.observation_id AND e.status='approved' "
            "WHERE o.batch_id=? ORDER BY o.observation_id",
            (batch_id,),
        ).fetchall()
        items: list[Observation] = []
        for row in rows:
            metrics = json.loads(row["metrics_json"])
            items.append(Observation(
                source_batch=row["source_batch"],
                source_row=row["source_row"],
                program_id=row["program_id"],
                protocol_id=protocol.protocol_id,
                protocol_version=protocol.version,
                stratum_key=row["stratum_key"],
                observed_at=row["observed_at"],
                metrics={key: Decimal(str(value)) for key, value in metrics.items()},
                excluded_reason=row["excluded_reason"],
            ))
        return tuple(items)

    def complete_job(self, worker_id: str, job_id: int, statistician_id: str) -> dict[str, Any]:
        self._require(statistician_id, "analysis.run")
        job = self.connection.execute("SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)).fetchone()
        if job is None:
            raise NotFound("分析任务不存在")
        if job["state"] != "leased" or job["lease_owner"] != worker_id:
            raise InvalidState("任务未由当前工作进程持有")
        if job["lease_expires_at"] <= self._now():
            raise InvalidState("任务租约已经过期")
        batch = self.get_batch(job["batch_id"])
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        observations = self._analysis_observations(batch["batch_id"], protocol)
        snapshot_rows = [
            {
                "source_batch": item.source_batch,
                "source_row": item.source_row,
                "stratum": item.stratum_key,
                "metrics": {key: format(value, "f") for key, value in item.metrics.items()},
                "excluded_reason": item.excluded_reason,
            }
            for item in observations
        ]
        input_digest = content_digest(snapshot_rows)
        result = analyze(protocol, observations)
        with transaction(self.connection, immediate=True):
            existing = self.connection.execute(
                "SELECT analysis_id,result_json FROM analyses WHERE batch_id=? AND batch_revision=? AND input_sha256=?",
                (batch["batch_id"], job["batch_revision"], input_digest),
            ).fetchone()
            if existing is None:
                cursor = self.connection.execute(
                    "INSERT INTO analyses(batch_id,batch_revision,protocol_sha256,input_sha256,algorithm_version,seed," 
                    "result_json,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        batch["batch_id"], job["batch_revision"], protocol_digest, input_digest,
                        ALGORITHM_VERSION, protocol.seed, canonical_json(result), statistician_id, self._now(),
                    ),
                )
                analysis_id = cursor.lastrowid
            else:
                analysis_id = existing["analysis_id"]
                result = json.loads(existing["result_json"])
            self.connection.execute(
                "UPDATE analysis_jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL,updated_at=? "
                "WHERE job_id=? AND state='leased' AND lease_owner=?",
                (self._now(), job_id, worker_id),
            )
            self.connection.execute(
                "UPDATE batches SET state='analyzed' WHERE batch_id=? AND state IN ('sealed','analyzing')",
                (batch["batch_id"],),
            )
            self._audit(
                "batch",
                batch["batch_id"],
                "analysis.completed",
                statistician_id,
                {"analysis_id": analysis_id, "input_sha256": input_digest},
            )
        return {"analysis_id": analysis_id, "input_sha256": input_digest, "result": result}

    def fail_job(self, worker_id: str, job_id: int, error: str, retry_seconds: int = 0) -> dict[str, Any]:
        available = isoformat(self.clock.now() + timedelta(seconds=retry_seconds))
        with transaction(self.connection, immediate=True):
            cursor = self.connection.execute(
                "UPDATE analysis_jobs SET state='queued',available_at=?,lease_owner=NULL,lease_expires_at=NULL," 
                "last_error=?,updated_at=? WHERE job_id=? AND state='leased' AND lease_owner=?",
                (available, error[:1000], self._now(), job_id, worker_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("任务未由当前工作进程持有")
        return {"job_id": job_id, "state": "queued", "available_at": available}

    def decide(
        self, actor_id: str, batch_id: str, analysis_id: int, decision: str, reason: str
    ) -> dict[str, Any]:
        self._require(actor_id, "decision.write")
        if decision not in {"needs_more_data", "approved", "rejected"}:
            raise ValidationFailed("未知分析准入决定")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["created_by"] == actor_id:
            raise Forbidden("统计负责人不能批准自己的分析")
        batch = self.get_batch(batch_id)
        if batch["state"] != "analyzed" or batch["revision"] != analysis_row["batch_revision"]:
            raise InvalidState("分析不是批次当前可审批版本")
        try:
            with transaction(self.connection, immediate=True):
                cursor = self.connection.execute(
                    "INSERT INTO decisions(batch_id,analysis_id,decision,reason,decided_by,decided_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (batch_id, analysis_id, decision, reason, actor_id, self._now()),
                )
                self.connection.execute("UPDATE batches SET state='decided' WHERE batch_id=?", (batch_id,))
                self._audit(
                    "batch",
                    batch_id,
                    "decision.recorded",
                    actor_id,
                    {"decision_id": cursor.lastrowid, "analysis_id": analysis_id, "decision": decision},
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("该分析版本已经形成决定") from exc
        return {"batch_id": batch_id, "analysis_id": analysis_id, "decision": decision}

    def report(self, actor_id: str, batch_id: str) -> dict[str, Any]:
        user = self._user(actor_id)
        if user["role"] not in {"statistician", "approver", "auditor"}:
            raise Forbidden("当前角色不能读取完整报告")
        batch = self.get_batch(batch_id)
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE batch_id=? ORDER BY analysis_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        decision_row = None
        if analysis_row is not None:
            decision_row = self.connection.execute(
                "SELECT * FROM decisions WHERE analysis_id=?", (analysis_row["analysis_id"],)
            ).fetchone()
        exclusions = self.connection.execute(
            "SELECT e.exclusion_id,e.observation_id,e.status,e.reason,e.requested_by,e.reviewed_by "
            "FROM exclusion_requests e JOIN observations o ON o.observation_id=e.observation_id "
            "WHERE o.batch_id=? ORDER BY e.exclusion_id", (batch_id,)
        ).fetchall()
        events = self.connection.execute(
            "SELECT event_type,actor_id,payload_json,created_at FROM audit_events "
            "WHERE entity_type='batch' AND entity_id=? "
            "ORDER BY event_id", (batch_id,)
        ).fetchall()
        return {
            "batch": batch,
            "protocol": {
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": None if analysis_row is None else {
                "analysis_id": analysis_row["analysis_id"],
                "input_sha256": analysis_row["input_sha256"],
                "algorithm_version": analysis_row["algorithm_version"],
                "created_by": analysis_row["created_by"],
                "result": json.loads(analysis_row["result_json"]),
            },
            "decision": None if decision_row is None else dict(decision_row),
            "exclusions": [dict(row) for row in exclusions],
            "events": [dict(row) | {"payload": json.loads(row["payload_json"])} for row in events],
        }

    # ------------------------------------------------------------------
    # 分级披露（tiered disclosure）
    # ------------------------------------------------------------------

    FORBIDDEN_DOCUMENT_KEYS = frozenset({
        "observation_id", "batch_id", "analysis_id", "decision_id",
        "exclusion_id", "user_id", "job_id",
    })

    def _active_signing_key(self) -> tuple[str, str]:
        row = self.connection.execute(
            "SELECT key_id,secret FROM disclosure_keys WHERE active=1 ORDER BY created_at DESC,key_id DESC LIMIT 1"
        ).fetchone()
        if row is not None:
            return row["key_id"], row["secret"]
        key_id = f"hk-{secrets.token_hex(8)}"
        secret = disclosure.generate_signing_key()
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO disclosure_keys(key_id,secret,active,created_at) VALUES(?,?,1,?)",
                (key_id, secret, self._now()),
            )
        return key_id, secret

    def rotate_disclosure_key(self, actor_id: str) -> dict[str, str]:
        """轮换签名密钥；旧包保留旧 key_id，仍可验旧签名。"""

        self._require(actor_id, "disclosure.admin")
        key_id = f"hk-{secrets.token_hex(8)}"
        secret = disclosure.generate_signing_key()
        with transaction(self.connection, immediate=True):
            self.connection.execute("UPDATE disclosure_keys SET active=0 WHERE active=1")
            self.connection.execute(
                "INSERT INTO disclosure_keys(key_id,secret,active,created_at) VALUES(?,?,1,?)",
                (key_id, secret, self._now()),
            )
            self._audit("disclosure", key_id, "disclosure.key_rotated", actor_id, {"key_id": key_id})
        return {"key_id": key_id}

    def _conclusion_source(
        self, batch_id: str, analysis_id: int, decision_id: int
    ) -> dict[str, Any]:
        batch = self.get_batch(batch_id)
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        decision_row = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=? AND analysis_id=? AND batch_id=?",
            (decision_id, analysis_id, batch_id),
        ).fetchone()
        if decision_row is None:
            raise NotFound("项目决定不存在或与分析版本不匹配")
        evidence_row = self.connection.execute(
            "SELECT er.version,er.content_sha256,p.program_id,p.program_name,p.lead_organization "
            "FROM evidence_revisions er JOIN cooperation_programs p ON p.program_id=er.program_id "
            "WHERE er.evidence_revision_id=?",
            (batch["evidence_revision_id"],),
        ).fetchone()
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        result = json.loads(analysis_row["result_json"])
        document = disclosure.build_conclusion_document(
            program={
                "program_id": evidence_row["program_id"],
                "program_name": evidence_row["program_name"],
                "lead_organization": evidence_row["lead_organization"],
            },
            evidence={"version": evidence_row["version"], "content_sha256": evidence_row["content_sha256"]},
            protocol={
                "protocol_id": protocol.protocol_id,
                "version": protocol.version,
                "sha256": protocol_digest,
            },
            analysis_result=result,
            decision={"decision": decision_row["decision"], "reason": decision_row["reason"]},
        )
        anchors = {
            "batch_revision": analysis_row["batch_revision"],
            "evidence_sha256": evidence_row["content_sha256"],
            "protocol_sha256": protocol_digest,
            "input_sha256": analysis_row["input_sha256"],
            "result_sha256": content_digest([result]),
            "decision_sha256": content_digest([
                {"decision": decision_row["decision"], "reason": decision_row["reason"]}
            ]),
        }
        return {"document": document, "anchors": anchors}

    def _assert_no_internal_references(self, value: Any, path: str = "$") -> None:
        if isinstance(value, Mapping):
            for key, item in value.items():
                if key in self.FORBIDDEN_DOCUMENT_KEYS:
                    raise ValidationFailed(f"披露文档不能包含内部标识: {path}.{key}")
                self._assert_no_internal_references(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._assert_no_internal_references(item, f"{path}[{index}]")
        elif isinstance(value, str) and ("http://" in value or "https://" in value):
            raise ValidationFailed(f"披露文档不能包含可沿引访问的链接: {path}")

    def _current_jurisdiction_regions(self, jurisdiction: str) -> tuple[str, ...] | None:
        row = self.connection.execute(
            "SELECT allowed_regions_json FROM disclosure_jurisdiction_policy "
            "WHERE jurisdiction=? ORDER BY changed_at DESC, rowid DESC LIMIT 1",
            (jurisdiction,),
        ).fetchone()
        return None if row is None else tuple(json.loads(row["allowed_regions_json"]))

    def _assert_residency_allowed(self, jurisdiction: str, regions: tuple[str, ...]) -> None:
        allowed = self._current_jurisdiction_regions(jurisdiction)
        if allowed is not None and not set(regions).issubset(set(allowed)):
            raise ValidationFailed(
                f"辖区 {jurisdiction} 当前数据驻留限制为 {sorted(allowed)}，不允许 {sorted(regions)}"
            )

    def issue_disclosure(
        self,
        actor_id: str,
        *,
        batch_id: str,
        analysis_id: int,
        decision_id: int,
        purpose: str,
        recipient: Mapping[str, Any],
        allowed_statements: Iterable[str],
        data_regions: Iterable[str],
        expires_at: str,
        redaction_rules: Iterable[str] | None = None,
        package_id: str | None = None,
    ) -> dict[str, Any]:
        """责任方冻结一份分级披露包并签名。"""

        self._require(actor_id, "disclosure.issue")
        if not isinstance(purpose, str) or not purpose.strip():
            raise ValidationFailed("使用目的不能为空")
        try:
            recipient_norm = disclosure.normalize_recipient(recipient)
            statements = disclosure.normalize_statements(tuple(allowed_statements))
            regions = disclosure.normalize_regions(tuple(data_regions))
            rules = disclosure.normalize_redaction_rules(
                tuple(redaction_rules) if redaction_rules is not None else None,
                recipient_norm["kind"],
            )
            expiry = disclosure.parse_expires_at(expires_at, now=self.clock.now())
        except disclosure.DisclosureError as exc:
            raise ValidationFailed(str(exc)) from exc
        self._assert_residency_allowed(recipient_norm["jurisdiction"], regions)
        source = self._conclusion_source(batch_id, analysis_id, decision_id)
        redacted_document = disclosure.apply_redactions(source["document"], rules)
        self._assert_no_internal_references(redacted_document)
        scope_sha = disclosure.scope_fingerprint(
            purpose=purpose.strip(),
            recipient=recipient_norm,
            allowed_statements=statements,
            redaction_rules=rules,
            data_regions=regions,
        )
        now = self.clock.now()
        # 同范围、同期限的重试直接返回原包，不产生新的授权或扩大范围。
        duplicate = self.connection.execute(
            "SELECT package_id FROM disclosure_packages "
            "WHERE decision_id=? AND scope_sha256=? AND expires_at=? AND status='active' LIMIT 1",
            (decision_id, scope_sha, isoformat(expiry)),
        ).fetchone()
        if duplicate is not None:
            self._audit("disclosure", duplicate["package_id"], "disclosure.issue_replayed", actor_id, {
                "scope_sha256": scope_sha,
            })
            return self.get_disclosure_envelope(actor_id, duplicate["package_id"]) | {"replayed": True}
        package_id = package_id or f"dp-{secrets.token_hex(10)}"
        manifest = disclosure.build_manifest(
            package_id=package_id,
            issued_at=now,
            expires_at=expiry,
            purpose=purpose.strip(),
            recipient=recipient_norm,
            allowed_statements=statements,
            redaction_rules=rules,
            data_regions=regions,
            anchors=source["anchors"],
            document=redacted_document,
            scope_sha256=scope_sha,
        )
        package = disclosure.build_package(manifest, redacted_document)
        key_id, secret = self._active_signing_key()
        signature = disclosure.sign_package(package, secret)
        pack = disclosure.envelope(package, signature)
        package_sha = pack["attestation"]["package_sha256"]
        frozen_text = canonical_json(pack)
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "INSERT INTO disclosure_packages("
                    "package_id,batch_id,decision_id,analysis_id,purpose,recipient_id,recipient_kind,"
                    "recipient_jurisdiction,allowed_statements_json,redaction_rules_json,data_regions_json,"
                    "issued_at,expires_at,status,scope_sha256,package_sha256,frozen_json,key_id,"
                    "signature_sha256,issued_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?)",
                    (
                        package_id, batch_id, decision_id, analysis_id, purpose.strip(),
                        recipient_norm["id"], recipient_norm["kind"], recipient_norm["jurisdiction"],
                        canonical_json(statements), canonical_json(rules), canonical_json(regions),
                        isoformat(now), isoformat(expiry),
                        scope_sha, package_sha, frozen_text, key_id, signature, actor_id, self._now(),
                    ),
                )
                self._audit("disclosure", package_id, "disclosure.issued", actor_id, {
                    "recipient_id": recipient_norm["id"],
                    "recipient_kind": recipient_norm["kind"],
                    "jurisdiction": recipient_norm["jurisdiction"],
                    "purpose": purpose.strip(),
                    "redaction_rules": rules,
                    "data_regions": regions,
                    "expires_at": isoformat(expiry),
                    "scope_sha256": scope_sha,
                    "package_sha256": package_sha,
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("披露包编号冲突") from exc
        return {"package_id": package_id, "status": "active", "replayed": False, "envelope": pack}

    def get_disclosure_envelope(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """内部读取冻结信封（不做门控、不记访问事实）。"""

        self._user(actor_id)
        row = self._disclosure_row(package_id)
        return {
            "package_id": package_id,
            "status": row["status"],
            "envelope": json.loads(row["frozen_json"]),
        }

    def _disclosure_row(self, package_id: str) -> sqlite3.Row:
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound("披露包不存在")
        return row

    def _record_access(
        self, row: sqlite3.Row, outcome: str, requester_id: str, deny_reason: str | None
    ) -> None:
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO disclosure_accesses("
                "package_id,package_sha256,recipient_id,purpose,outcome,deny_reason,actor_id,accessed_at) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (
                    row["package_id"], row["package_sha256"], requester_id, row["purpose"],
                    outcome, deny_reason, requester_id, self._now(),
                ),
            )
            self._audit("disclosure", row["package_id"], f"disclosure.access.{outcome}", requester_id, {
                "recipient_id": requester_id,
                "intended_recipient_id": row["recipient_id"],
                "purpose": row["purpose"],
                "deny_reason": deny_reason,
            })

    def _transition_status(self, row: sqlite3.Row, new_status: str, reason: str) -> None:
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE disclosure_packages SET status=? WHERE package_id=? AND status='active'",
                (new_status, row["package_id"]),
            )
            self._audit("disclosure", row["package_id"], f"disclosure.status.{new_status}", "system", {
                "reason": reason,
            })

    def _effective_status(self, row: sqlite3.Row) -> str:
        """不写库地计算当前生效状态，供只读台账使用。"""

        if row["status"] != "active":
            return row["status"]
        if isoformat(self.clock.now()) >= row["expires_at"]:
            return "expired"
        if self.connection.execute(
            "SELECT 1 FROM decision_invalidations WHERE decision_id=?", (row["decision_id"],)
        ).fetchone() is not None:
            return "decision_invalid"
        allowed = self._current_jurisdiction_regions(row["recipient_jurisdiction"])
        if allowed is not None and not set(json.loads(row["data_regions_json"])).issubset(set(allowed)):
            return "jurisdiction_blocked"
        return "active"

    def _gate_status(self, row: sqlite3.Row) -> str:
        """评估门控；到期和辖区变化在首次访问时惰性落状态。"""

        effective = self._effective_status(row)
        if effective != "active" and row["status"] == "active":
            reasons = {
                "expired": "授权到期",
                "decision_invalid": "项目决定失效",
                "jurisdiction_blocked": "辖区数据驻留限制变化",
            }
            self._transition_status(row, effective, reasons[effective])
        return effective

    def read_disclosure(self, recipient_id: str, package_id: str) -> dict[str, Any]:
        """接收方读取披露包；门控失败同样留下访问事实。"""

        row = self._disclosure_row(package_id)
        actor = recipient_id.strip()
        if not actor:
            raise ValidationFailed("缺少接收主体标识")
        if row["recipient_id"] != actor:
            self._record_access(row, "denied", actor, "接收主体与披露包不匹配")
            raise Forbidden("接收主体与披露包不匹配")
        status = self._gate_status(row)
        if status != "active":
            reasons = {
                "revoked": "授权已主动撤回",
                "expired": "授权已到期",
                "decision_invalid": "项目决定已失效",
                "jurisdiction_blocked": "辖区数据驻留限制变化",
            }
            reason = reasons[status]
            self._record_access(row, "denied", actor, reason)
            raise DisclosureDenied(reason)
        self._record_access(row, "delivered", actor, None)
        return {"package_id": package_id, "status": "active", "envelope": json.loads(row["frozen_json"])}

    def revoke_disclosure(self, actor_id: str, package_id: str, reason: str) -> dict[str, str]:
        self._require(actor_id, "disclosure.revoke")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("撤回原因不能为空")
        row = self._disclosure_row(package_id)
        if row["status"] != "active":
            raise InvalidState(f"披露包当前状态 {row['status']}，不能撤回")
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "UPDATE disclosure_packages SET status='revoked',revoked_at=?,revoke_reason=? "
                "WHERE package_id=? AND status='active'",
                (self._now(), reason.strip(), package_id),
            )
            self._audit("disclosure", package_id, "disclosure.revoked", actor_id, {
                "reason": reason.strip(),
                "scope_sha256": row["scope_sha256"],
            })
        return {"package_id": package_id, "status": "revoked"}

    def resign_disclosure(
        self, actor_id: str, package_id: str, *, new_expires_at: str, reason: str
    ) -> dict[str, Any]:
        """以相同授权范围重签续期；旧包标记被替代，范围指纹必须一致。"""

        self._require(actor_id, "disclosure.resign")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("重签原因不能为空")
        row = self._disclosure_row(package_id)
        if row["status"] != "active":
            raise InvalidState(f"披露包当前状态 {row['status']}，不能重签")
        try:
            new_expiry = disclosure.parse_expires_at(new_expires_at, now=self.clock.now())
        except disclosure.DisclosureError as exc:
            raise ValidationFailed(str(exc)) from exc
        if isoformat(new_expiry) <= row["expires_at"]:
            raise ValidationFailed("重签的有效期限必须晚于原有效期限")
        old_envelope = json.loads(row["frozen_json"])
        old_manifest = old_envelope["manifest"]
        issued_at = self._now()
        new_id = f"dp-{secrets.token_hex(10)}"
        new_manifest = {
            **old_manifest,
            "package_id": new_id,
            "issued_at": issued_at,
            "expires_at": isoformat(new_expiry),
        }
        new_package = {"manifest": new_manifest, "document": old_envelope["document"]}
        key_id, secret = self._active_signing_key()
        signature = disclosure.sign_package(new_package, secret)
        new_envelope = disclosure.envelope(new_package, signature)
        if new_manifest["scope_sha256"] != row["scope_sha256"]:
            raise InvalidState("重签后范围指纹发生变化，拒绝重签")
        try:
            with transaction(self.connection, immediate=True):
                self.connection.execute(
                    "UPDATE disclosure_packages SET status='revoked',revoked_at=?,revoke_reason=? "
                    "WHERE package_id=? AND status='active'",
                    (self._now(), f"重签替代 {new_id}: {reason.strip()}", package_id),
                )
                self.connection.execute(
                    "INSERT INTO disclosure_packages("
                    "package_id,batch_id,decision_id,analysis_id,purpose,recipient_id,recipient_kind,"
                    "recipient_jurisdiction,allowed_statements_json,redaction_rules_json,data_regions_json,"
                    "issued_at,expires_at,status,scope_sha256,package_sha256,frozen_json,key_id,"
                    "signature_sha256,issued_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?)",
                    (
                        new_id, row["batch_id"], row["decision_id"], row["analysis_id"], row["purpose"],
                        row["recipient_id"], row["recipient_kind"], row["recipient_jurisdiction"],
                        row["allowed_statements_json"], row["redaction_rules_json"], row["data_regions_json"],
                        issued_at, isoformat(new_expiry),
                        row["scope_sha256"], new_envelope["attestation"]["package_sha256"],
                        canonical_json(new_envelope), key_id, signature, actor_id, self._now(),
                    ),
                )
                self.connection.execute(
                    "INSERT INTO disclosure_resignings("
                    "old_package_id,new_package_id,reason,scope_sha256,requested_by,created_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (package_id, new_id, reason.strip(), row["scope_sha256"], actor_id, self._now()),
                )
                self._audit("disclosure", package_id, "disclosure.resigned", actor_id, {
                    "new_package_id": new_id,
                    "scope_sha256": row["scope_sha256"],
                })
        except sqlite3.IntegrityError as exc:
            raise Conflict("重签并发冲突") from exc
        return {"package_id": new_id, "status": "active", "envelope": new_envelope}

    def invalidate_decision(self, actor_id: str, decision_id: int, reason: str) -> dict[str, Any]:
        self._require(actor_id, "disclosure.admin")
        if not isinstance(reason, str) or not reason.strip():
            raise ValidationFailed("失效原因不能为空")
        decision_row = self.connection.execute(
            "SELECT decision_id,batch_id FROM decisions WHERE decision_id=?", (decision_id,)
        ).fetchone()
        if decision_row is None:
            raise NotFound("项目决定不存在")
        affected: list[str] = []
        with transaction(self.connection, immediate=True):
            try:
                self.connection.execute(
                    "INSERT INTO decision_invalidations(decision_id,batch_id,reason,invalidated_by,invalidated_at) "
                    "VALUES(?,?,?,?,?)",
                    (decision_id, decision_row["batch_id"], reason.strip(), actor_id, self._now()),
                )
            except sqlite3.IntegrityError as exc:
                raise Conflict("该决定已经登记失效") from exc
            self.connection.execute(
                "UPDATE batches SET state='invalidated' WHERE batch_id=?",
                (decision_row["batch_id"],),
            )
            active = self.connection.execute(
                "SELECT package_id FROM disclosure_packages WHERE decision_id=? AND status='active'",
                (decision_id,),
            ).fetchall()
            for item in active:
                self.connection.execute(
                    "UPDATE disclosure_packages SET status='decision_invalid' WHERE package_id=?",
                    (item["package_id"],),
                )
                affected.append(item["package_id"])
                self._audit(
                    "disclosure", item["package_id"], "disclosure.status.decision_invalid", actor_id,
                    {"reason": reason.strip(), "decision_id": decision_id},
                )
            self._audit("decision", str(decision_id), "decision.invalidated", actor_id, {
                "reason": reason.strip(), "affected_packages": affected,
            })
        return {"decision_id": decision_id, "affected_packages": affected}

    def set_jurisdiction_restriction(
        self, actor_id: str, jurisdiction: str, allowed_regions: Iterable[str]
    ) -> dict[str, Any]:
        self._require(actor_id, "disclosure.admin")
        if not isinstance(jurisdiction, str) or not jurisdiction.strip():
            raise ValidationFailed("辖区不能为空")
        try:
            regions = disclosure.normalize_regions(tuple(allowed_regions))
        except disclosure.DisclosureError as exc:
            raise ValidationFailed(str(exc)) from exc
        jurisdiction = jurisdiction.strip().upper()
        affected: list[str] = []
        with transaction(self.connection, immediate=True):
            self.connection.execute(
                "INSERT INTO disclosure_jurisdiction_policy(jurisdiction,allowed_regions_json,changed_at,changed_by) "
                "VALUES(?,?,?,?)",
                (jurisdiction, canonical_json(regions), self._now(), actor_id),
            )
            active = self.connection.execute(
                "SELECT package_id,data_regions_json FROM disclosure_packages "
                "WHERE recipient_jurisdiction=? AND status='active'",
                (jurisdiction,),
            ).fetchall()
            for item in active:
                if not set(json.loads(item["data_regions_json"])).issubset(set(regions)):
                    self.connection.execute(
                        "UPDATE disclosure_packages SET status='jurisdiction_blocked' WHERE package_id=?",
                        (item["package_id"],),
                    )
                    affected.append(item["package_id"])
                    self._audit(
                        "disclosure", item["package_id"], "disclosure.status.jurisdiction_blocked",
                        actor_id, {"allowed_regions": regions},
                    )
            self._audit("jurisdiction", jurisdiction, "jurisdiction.restriction_changed", actor_id, {
                "allowed_regions": regions, "affected_packages": affected,
            })
        return {"jurisdiction": jurisdiction, "allowed_regions": list(regions), "affected_packages": affected}

    def verify_disclosure(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """校验冻结信封的内容摘要、来源签名、范围指纹和遮蔽锚点。"""

        self._require(actor_id, "audit.read")
        row = self._disclosure_row(package_id)
        envelope = json.loads(row["frozen_json"])
        body = {"manifest": envelope["manifest"], "document": envelope["document"]}
        attestation = envelope["attestation"]
        key_row = self.connection.execute(
            "SELECT secret FROM disclosure_keys WHERE key_id=?", (row["key_id"],)
        ).fetchone()
        signature_valid = disclosure.verify_signature(body, row["signature_sha256"], key_row["secret"])
        digest_match = attestation["package_sha256"] == disclosure.package_digest(body)
        document_digest = hashlib.sha256(
            canonical_json(envelope["document"]).encode("utf-8")
        ).hexdigest()
        document_match = envelope["manifest"]["document_sha256"] == document_digest
        recipient = {
            "id": row["recipient_id"],
            "kind": row["recipient_kind"],
            "jurisdiction": row["recipient_jurisdiction"],
        }
        scope_recomputed = disclosure.scope_fingerprint(
            purpose=row["purpose"],
            recipient=recipient,
            allowed_statements=json.loads(row["allowed_statements_json"]),
            redaction_rules=json.loads(row["redaction_rules_json"]),
            data_regions=json.loads(row["data_regions_json"]),
        )
        # 用当前数据库中的完整记录重算被遮蔽字段摘要，验证声明确实锚定原证据。
        source = self._conclusion_source(row["batch_id"], row["analysis_id"], row["decision_id"])
        anchor_checks: list[dict[str, Any]] = []
        for pointer in json.loads(row["redaction_rules_json"]):
            node, key = disclosure._walk_pointer(source["document"], pointer)
            marker = disclosure._walk_pointer(envelope["document"], pointer)[0][key]
            expected = hashlib.sha256(
                canonical_json(node[key]).encode("utf-8")
            ).hexdigest()
            anchor_checks.append({
                "path": pointer,
                "verified": marker.get(disclosure.REDACTION_MARKER) is True
                and marker.get("sha256") == expected,
            })
        anchors = envelope["manifest"]["anchors"]
        anchor_digests = {
            "evidence_sha256": source["anchors"]["evidence_sha256"],
            "protocol_sha256": source["anchors"]["protocol_sha256"],
            "input_sha256": source["anchors"]["input_sha256"],
            "result_sha256": source["anchors"]["result_sha256"],
            "decision_sha256": source["anchors"]["decision_sha256"],
        }
        anchor_links = {
            key: {"claimed": anchors[key], "verified": anchors[key] == current}
            for key, current in anchor_digests.items()
        }
        return {
            "package_id": package_id,
            "status": row["status"],
            "package_sha256_match": digest_match,
            "signature_valid": signature_valid,
            "scope_sha256_match": scope_recomputed == row["scope_sha256"],
            "document_sha256_match": document_match,
            "redaction_anchors": anchor_checks,
            "redaction_anchors_verified": all(item["verified"] for item in anchor_checks),
            "evidence_anchors": anchor_links,
            "evidence_anchors_verified": all(item["verified"] for item in anchor_links.values()),
        }

    def disclosure_ledger(self, actor_id: str) -> dict[str, Any]:
        """合规台账：谁在何时因何目的看到哪些内容，以及范围是否被扩大。"""

        self._require(actor_id, "disclosure.ledger")
        package_rows = self.connection.execute(
            "SELECT * FROM disclosure_packages ORDER BY created_at,package_id"
        ).fetchall()
        packages: list[dict[str, Any]] = []
        scope_by_id: dict[str, str] = {}
        for row in package_rows:
            recipient = {
                "id": row["recipient_id"],
                "kind": row["recipient_kind"],
                "jurisdiction": row["recipient_jurisdiction"],
            }
            scope_recomputed = disclosure.scope_fingerprint(
                purpose=row["purpose"],
                recipient=recipient,
                allowed_statements=json.loads(row["allowed_statements_json"]),
                redaction_rules=json.loads(row["redaction_rules_json"]),
                data_regions=json.loads(row["data_regions_json"]),
            )
            scope_by_id[row["package_id"]] = row["scope_sha256"]
            envelope = json.loads(row["frozen_json"])
            packages.append({
                "package_id": row["package_id"],
                "batch_id": row["batch_id"],
                "decision_id": row["decision_id"],
                "status": row["status"],
                "effective_status": self._effective_status(row),
                "purpose": row["purpose"],
                "recipient": recipient,
                "allowed_statements": json.loads(row["allowed_statements_json"]),
                "redaction_rules": json.loads(row["redaction_rules_json"]),
                "data_regions": json.loads(row["data_regions_json"]),
                "issued_at": row["issued_at"],
                "expires_at": row["expires_at"],
                "revoked_at": row["revoked_at"],
                "revoke_reason": row["revoke_reason"],
                "scope_sha256": row["scope_sha256"],
                "scope_sha256_match": scope_recomputed == row["scope_sha256"],
                "package_sha256": row["package_sha256"],
                "document_sha256": envelope["manifest"]["document_sha256"],
                "issued_by": row["issued_by"],
            })
        access_rows = self.connection.execute(
            "SELECT a.* FROM disclosure_accesses a ORDER BY a.access_id"
        ).fetchall()
        accesses = [
            {
                "accessed_at": row["accessed_at"],
                "recipient_id": row["recipient_id"],
                "purpose": row["purpose"],
                "package_id": row["package_id"],
                "package_sha256": row["package_sha256"],
                "outcome": row["outcome"],
                "deny_reason": row["deny_reason"],
                "actor_id": row["actor_id"],
            }
            for row in access_rows
        ]
        resign_rows = self.connection.execute(
            "SELECT * FROM disclosure_resignings ORDER BY resigning_id"
        ).fetchall()
        resignings = []
        resign_scope_ok = True
        for row in resign_rows:
            old_scope = scope_by_id.get(row["old_package_id"])
            new_scope = scope_by_id.get(row["new_package_id"])
            ok = old_scope == new_scope == row["scope_sha256"]
            resign_scope_ok = resign_scope_ok and ok
            resignings.append({
                "old_package_id": row["old_package_id"],
                "new_package_id": row["new_package_id"],
                "reason": row["reason"],
                "scope_unchanged": ok,
                "requested_by": row["requested_by"],
                "created_at": row["created_at"],
            })
        delivered = [
            {
                "accessed_at": item["accessed_at"],
                "recipient_id": item["recipient_id"],
                "purpose": item["purpose"],
                "package_id": item["package_id"],
                "package_sha256": item["package_sha256"],
                "redaction_rules": next(
                    p["redaction_rules"] for p in packages if p["package_id"] == item["package_id"]
                ),
                "document_sha256": next(
                    p["document_sha256"] for p in packages if p["package_id"] == item["package_id"]
                ),
            }
            for item in accesses if item["outcome"] == "delivered"
        ]
        return {
            "packages": packages,
            "accesses": accesses,
            "resignings": resignings,
            "delivered_view": delivered,
            "scope_integrity": (
                all(p["scope_sha256_match"] for p in packages) and resign_scope_ok
            ),
        }
