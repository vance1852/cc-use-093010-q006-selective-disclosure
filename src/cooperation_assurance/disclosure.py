"""分级披露：遮蔽策略、内容冻结、来源封签与访问控制。

设计边界：
- 披露内容只包含汇总结论与元数据；原始观测永不进入披露包，包内仅保留原证据的
  SHA-256 锚点，接收方无法凭锚点访问未授权记录。
- 字段策略采用“默认遮蔽”：未在 reveal_paths 中显式放开的字段一律遮蔽，
  避免责任方漏配导致泄密。
- 被遮蔽字段以 HMAC 承诺值保留与原证据值的可验证关联；包指纹与封签覆盖全部内容，
  重签只更换签名块，载荷字节与范围指纹保持不变。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .clock import isoformat
from .errors import Forbidden, InvalidState, NotFound, ValidationFailed
from .jsonio import canonical_json
from .storage import transaction

DISCLOSURE_SCHEMA = "cooperation-assurance/disclosure@1"
SIGNATURE_ALGORITHM = "HMAC-SHA256"

RECIPIENT_CLASSES = ("foreign_investor", "local_regulator", "independent_assessor")
PURPOSE_CODES = ("due_diligence", "regulatory_filing", "independent_assessment")

# 可配置字段目录：全部默认遮蔽。path 指向冻结内容中的 JSON 路径。
FIELD_CATALOG: dict[str, dict[str, str]] = {
    "program.program_name": {"sensitivity": "commercial", "label": "项目名称"},
    "program.lead_organization": {"sensitivity": "commercial", "label": "牵头机构"},
    "evidence_revision.version": {"sensitivity": "commercial", "label": "证据版本号"},
    "batch.state": {"sensitivity": "operational", "label": "批次状态"},
    "batch.revision": {"sensitivity": "operational", "label": "批次修订号"},
    "protocol.title_dup": {"sensitivity": "operational", "label": "占位（不会使用）"},
    "protocol.title": {"sensitivity": "operational", "label": "协议标题"},
    "protocol.task_family": {"sensitivity": "operational", "label": "任务族"},
    "protocol.seed": {"sensitivity": "technical", "label": "随机种子"},
    "protocol.bootstrap_samples": {"sensitivity": "technical", "label": "自抽样次数"},
    "analysis.algorithm_version": {"sensitivity": "technical", "label": "算法版本"},
    "analysis.result.conclusion": {"sensitivity": "conclusion", "label": "评估结论"},
    "analysis.result.included_count": {"sensitivity": "statistic", "label": "纳入样本数"},
    "analysis.result.excluded_count": {"sensitivity": "statistic", "label": "排除样本数"},
    "analysis.result.aggregate": {"sensitivity": "statistic", "label": "汇总指标"},
    "analysis.result.rules": {"sensitivity": "statistic", "label": "准入规则结果"},
    "analysis.result.insufficient": {"sensitivity": "statistic", "label": "覆盖不足明细"},
    "analysis.result.strata": {"sensitivity": "commercial", "label": "分层明细"},
    "analysis.result.seed": {"sensitivity": "technical", "label": "分析随机种子"},
    "analysis.result.bootstrap_samples": {"sensitivity": "technical", "label": "分析自抽样次数"},
    "decision.decision": {"sensitivity": "conclusion", "label": "准入决定"},
    "decision.reason": {"sensitivity": "commercial", "label": "决定理由"},
    "decision.decided_by": {"sensitivity": "identity", "label": "决定人"},
    "decision.decided_at": {"sensitivity": "operational", "label": "决定时间"},
}
FIELD_CATALOG.pop("protocol.title_dup")

CONTROLLABLE_PATHS = frozenset(FIELD_CATALOG)


def parse_iso(value: object, path: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(f"{path} 必须是 ISO-8601 时间字符串")
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationFailed(f"{path} 不是有效时间") from exc
    if parsed.tzinfo is None:
        raise ValidationFailed(f"{path} 必须携带时区")
    return parsed.astimezone(timezone.utc)


def _walk(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            raise ValidationFailed(f"字段路径不存在: {path}")
        current = current[part]
    return current


def _replace(value: dict[str, Any], path: str, replacement: Any) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        current = current[part]
    current[parts[-1]] = replacement


def _is_ancestor(ancestor: str, path: str) -> bool:
    return path.startswith(ancestor + ".")


def normalize_field_policy(raw: Mapping[str, Any]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    reveal = raw.get("reveal_paths", [])
    redact = raw.get("redact_paths", [])
    if not isinstance(reveal, list) or not isinstance(redact, list):
        raise ValidationFailed("field_policy.reveal_paths 与 redact_paths 必须是数组")
    reveal_paths = tuple(str(item) for item in reveal)
    redact_paths = tuple(str(item) for item in redact)
    for path in (*reveal_paths, *redact_paths):
        if path not in CONTROLLABLE_PATHS:
            raise ValidationFailed(f"未知或不可配置的字段路径: {path}")
    if len(set(reveal_paths)) != len(reveal_paths) or len(set(redact_paths)) != len(redact_paths):
        raise ValidationFailed("遮蔽规则中的字段路径不能重复")
    overlap = set(reveal_paths) & set(redact_paths)
    if overlap:
        raise ValidationFailed(f"字段不能同时放开与遮蔽: {sorted(overlap)}")
    # 父路径被遮蔽时，不能显式放开子路径，否则承诺与可见内容矛盾。
    for path in reveal_paths:
        for hidden in redact_paths:
            if _is_ancestor(hidden, path):
                raise ValidationFailed(f"{path} 的上级 {hidden} 已被遮蔽，不能单独放开")
    return reveal_paths, redact_paths


def redact_content(
    content: Mapping[str, Any],
    reveal_paths: tuple[str, ...],
    redact_paths: tuple[str, ...],
    secret: bytes,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """按默认遮蔽策略生成披露内容与字段清单（含遮蔽承诺）。"""

    visible = dict(content)
    revealed = set(reveal_paths)
    explicitly_redacted = set(redact_paths)
    manifest: list[dict[str, Any]] = []

    def commitment(path: str, value: Any) -> str:
        digest = hmac.new(secret, b"commitment\x00" + path.encode("utf-8") + b"\x00", hashlib.sha256)
        digest.update(canonical_json(value).encode("utf-8"))
        return digest.hexdigest()

    for path in sorted(CONTROLLABLE_PATHS):
        inside_redacted_subtree = any(
            hidden != path and _is_ancestor(hidden, path) and hidden not in revealed
            for hidden in explicitly_redacted
        )
        if path in revealed:
            status = "revealed"
        elif inside_redacted_subtree:
            status = "redacted_with_parent"
        else:
            status = "redacted"
        entry: dict[str, Any] = {"path": path, "status": status}
        if status == "revealed":
            entry["commitment"] = None
        elif status == "redacted":
            entry["commitment"] = commitment(path, _walk(content, path))
        else:
            entry["commitment"] = None
        manifest.append(entry)

    # 以“最长路径优先”应用遮蔽，保证父级承诺覆盖整个子树。
    for path in sorted(explicitly_redacted, key=lambda item: (-len(item), item)):
        if any(other != path and _is_ancestor(other, path) for other in explicitly_redacted):
            continue
        _replace(visible, path, {"redacted": True, "commitment": commitment(path, _walk(content, path))})
    for path in sorted(CONTROLLABLE_PATHS - revealed - explicitly_redacted):
        if any(_is_ancestor(hidden, path) for hidden in explicitly_redacted):
            continue
        _replace(visible, path, {"redacted": True, "commitment": commitment(path, _walk(content, path))})
    return visible, manifest


def scope_fingerprint(scope: Mapping[str, Any]) -> str:
    """范围指纹：版本、目的、接收方、声明、遮蔽规则与期限；不含辖区临时收窄。"""

    material = [
        "disclosure-scope/1",
        scope["batch_id"],
        scope["analysis_id"],
        scope["decision_id"],
        scope["purpose_code"],
        scope["purpose_detail"],
        scope["recipient_class"],
        sorted(scope["recipients"], key=lambda item: item["recipient_id"]),
        sorted(scope["allowed_statements"]),
        scope["effective_at"],
        scope["expires_at"],
        sorted(scope["reveal_paths"]),
        sorted(scope["redact_paths"]),
    ]
    digest = hashlib.sha256()
    for item in material:
        digest.update(canonical_json(item).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest()


def sign_payload(payload: Mapping[str, Any], secret: bytes, key_id: str, key_seq: int) -> dict[str, Any]:
    package_sha256 = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    signature = hmac.new(secret, package_sha256.encode("ascii"), hashlib.sha256).hexdigest()
    return {
        "alg": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "key_seq": key_seq,
        "digest": package_sha256,
        "value": signature,
    }


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class DisclosureMixin:
    """挂在 AssuranceService 上的分级披露用例。"""

    def rotate_signing_key(self, actor_id: str) -> dict[str, str]:
        self._require(actor_id, "disclosure.manage")
        now = self._now()
        with transaction(
            self.connection, immediate=True
        ):
            self.connection.execute("UPDATE sealing_keys SET state='retired', retired_at=? WHERE state='active'", (now,))
            count = self.connection.execute("SELECT count(*) FROM sealing_keys").fetchone()[0]
            key_id = f"seal-key-{count + 1}"
            secret = base64.b64encode(os.urandom(32)).decode("ascii")
            self.connection.execute(
                "INSERT INTO sealing_keys(key_id,secret_b64,state,created_at) VALUES(?,?, 'active', ?)",
                (key_id, secret, now),
            )
            self._audit("signing_key", key_id, "signing_key.rotated", actor_id, {"replaced": count})
        return {"key_id": key_id, "state": "active"}

    def _active_signing_key(self) -> tuple[str, bytes]:
        row = self.connection.execute(
            "SELECT key_id,secret_b64 FROM sealing_keys WHERE state='active'"
        ).fetchone()
        if row is None:
            raise InvalidState("尚无启用的封签密钥，请先轮换密钥")
        return row["key_id"], base64.b64decode(row["secret_b64"])

    def _signing_key(self, key_id: str) -> bytes:
        row = self.connection.execute(
            "SELECT secret_b64 FROM sealing_keys WHERE key_id=?", (key_id,)
        ).fetchone()
        if row is None:
            raise InvalidState(f"封签密钥已不存在: {key_id}")
        return base64.b64decode(row["secret_b64"])

    def _disclosure_material(
        self,
        program_row,
        ev_row,
        batch,
        protocol,
        protocol_digest: str,
        analysis_row,
        result: Mapping[str, Any],
        decision_row,
        purpose_code: str,
        purpose_detail: str,
        recipient_class: str,
        recipients: list[dict[str, str]],
        statements: list[str],
        jurisdictions: list[str],
        effective_at: str,
        expires_at: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        content: dict[str, Any] = {
            "program": {
                "program_name": program_row["program_name"],
                "lead_organization": program_row["lead_organization"],
            },
            "evidence_revision": {"version": ev_row["version"]},
            "batch": {"state": batch["state"], "revision": batch["revision"]},
            "protocol": {
                "title": protocol.title,
                "task_family": protocol.task_family,
                "seed": protocol.seed,
                "bootstrap_samples": protocol.bootstrap_samples,
            },
            "analysis": {"algorithm_version": analysis_row["algorithm_version"], "result": result},
            "decision": {
                "decision": decision_row["decision"],
                "reason": decision_row["reason"],
                "decided_by": decision_row["decided_by"],
                "decided_at": decision_row["decided_at"],
            },
            "purpose": {"code": purpose_code, "detail": purpose_detail},
            "recipient_class": recipient_class,
            "recipients": recipients,
            "permitted_statements": statements,
            "jurisdictions_at_issuance": jurisdictions,
            "effective_at": effective_at,
            "expires_at": expires_at,
        }
        anchors = {
            "program_id": program_row["program_id"],
            "evidence_revision_id": ev_row["evidence_revision_id"],
            "evidence_sha256": ev_row["content_sha256"],
            "batch_id": batch["batch_id"],
            "batch_revision": batch["revision"],
            "protocol_id": protocol.protocol_id,
            "protocol_version": protocol.version,
            "protocol_sha256": protocol_digest,
            "analysis_id": analysis_row["analysis_id"],
            "analysis_input_sha256": analysis_row["input_sha256"],
            "decision_id": decision_row["decision_id"],
        }
        return content, anchors

    def create_disclosure_package(
        self, actor_id: str, request: Mapping[str, Any]
    ) -> dict[str, Any]:
        self._require(actor_id, "disclosure.manage")
        package_id = str(request.get("package_id", "")).strip()
        if not package_id:
            raise ValidationFailed("package_id 不能为空")
        batch_id = str(request.get("batch_id", "")).strip()
        analysis_id = request.get("analysis_id")
        decision_id = request.get("decision_id")
        if not isinstance(analysis_id, int) or isinstance(analysis_id, bool):
            raise ValidationFailed("analysis_id 必须是整数")
        if not isinstance(decision_id, int) or isinstance(decision_id, bool):
            raise ValidationFailed("decision_id 必须是整数")

        purpose_code = str(request.get("purpose_code", "")).strip()
        if purpose_code not in PURPOSE_CODES:
            raise ValidationFailed(f"purpose_code 必须是 {PURPOSE_CODES} 之一")
        purpose_detail = str(request.get("purpose_detail", "")).strip()
        if not purpose_detail:
            raise ValidationFailed("purpose_detail 不能为空")
        recipient_class = str(request.get("recipient_class", "")).strip()
        if recipient_class not in RECIPIENT_CLASSES:
            raise ValidationFailed(f"recipient_class 必须是 {RECIPIENT_CLASSES} 之一")

        raw_recipients = request.get("recipients", [])
        if not isinstance(raw_recipients, list) or not raw_recipients:
            raise ValidationFailed("recipients 至少包含一个接收主体")
        recipients: list[dict[str, str]] = []
        for index, item in enumerate(raw_recipients):
            if not isinstance(item, Mapping):
                raise ValidationFailed(f"recipients[{index}] 必须是对象")
            recipient_id = str(item.get("recipient_id", "")).strip()
            name = str(item.get("name", "")).strip()
            jurisdiction = str(item.get("jurisdiction", "")).strip()
            if not recipient_id or not name or not jurisdiction:
                raise ValidationFailed(f"recipients[{index}] 的编号、名称和辖区均不能为空")
            recipients.append({"recipient_id": recipient_id, "name": name, "jurisdiction": jurisdiction})
        if len({item["recipient_id"] for item in recipients}) != len(recipients):
            raise ValidationFailed("接收主体编号不能重复")

        statements = request.get("allowed_statements", [])
        if not isinstance(statements, list) or not statements or any(
            not isinstance(item, str) or not item.strip() for item in statements
        ):
            raise ValidationFailed("allowed_statements 必须是非空字符串数组")
        statements = sorted({item.strip() for item in statements})

        jurisdictions = request.get("jurisdictions", [])
        if not isinstance(jurisdictions, list) or not jurisdictions or any(
            not isinstance(item, str) or not item.strip() for item in jurisdictions
        ):
            raise ValidationFailed("jurisdictions 必须是非空辖区代码数组")
        jurisdictions = sorted({item.strip() for item in jurisdictions})

        if any(item["jurisdiction"] not in jurisdictions for item in recipients):
            raise ValidationFailed("接收主体的注册辖区必须包含在授权辖区列表中")

        raw_policy = request.get("field_policy", {})
        if not isinstance(raw_policy, Mapping):
            raise ValidationFailed("field_policy 必须是对象")
        reveal_paths, redact_paths = normalize_field_policy(raw_policy)
        if not reveal_paths:
            raise ValidationFailed("至少需要显式放开一个字段，否则披露包不包含任何可见结论")

        now = self.clock.now()
        effective = (
            parse_iso(request.get("effective_at"), "effective_at")
            if request.get("effective_at") is not None
            else now
        )
        expires = parse_iso(request.get("expires_at"), "expires_at")
        if expires <= effective:
            raise ValidationFailed("expires_at 必须晚于 effective_at")
        retain_days = request.get("retain_days", 365)
        if isinstance(retain_days, bool) or not isinstance(retain_days, int) or retain_days < 1:
            raise ValidationFailed("retain_days 必须是大于零的整数")
        effective_at = isoformat(effective)
        expires_at = isoformat(expires)
        retain_until = isoformat(expires + timedelta(days=retain_days))

        # 结论版本必须是项目当前生效的决定，冻结的就是“确定版本”。
        batch = self.get_batch(batch_id)
        if batch["state"] != "decided":
            raise InvalidState("只有已形成准入决定的批次可以对外披露")
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=? AND batch_id=?", (analysis_id, batch_id)
        ).fetchone()
        if analysis_row is None:
            raise NotFound("分析版本不存在")
        if analysis_row["batch_revision"] != batch["revision"]:
            raise InvalidState("分析版本不是批次当前版本，不能冻结披露")
        decision_row = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=? AND analysis_id=? AND batch_id=?",
            (decision_id, analysis_id, batch_id),
        ).fetchone()
        if decision_row is None:
            raise NotFound("决定不存在或不属于该分析版本")
        latest_decision = self.connection.execute(
            "SELECT decision_id FROM decisions WHERE batch_id=? ORDER BY decision_id DESC LIMIT 1", (batch_id,)
        ).fetchone()
        if latest_decision["decision_id"] != decision_id:
            raise InvalidState("该决定已被后续决定取代，不能作为披露结论")

        ev_row = self.connection.execute(
            "SELECT * FROM evidence_revisions WHERE evidence_revision_id=?", (batch["evidence_revision_id"],)
        ).fetchone()
        program_row = self.connection.execute(
            "SELECT * FROM cooperation_programs WHERE program_id=?", (ev_row["program_id"],)
        ).fetchone()
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])
        result = json.loads(analysis_row["result_json"])

        content, anchors = self._disclosure_material(
            program_row, ev_row, batch, protocol, protocol_digest, analysis_row, result, decision_row,
            purpose_code, purpose_detail, recipient_class, recipients, statements, jurisdictions,
            effective_at, expires_at,
        )

        key_id, secret = self._active_signing_key()
        visible, manifest = redact_content(content, reveal_paths, redact_paths, secret)
        scope = {
            "batch_id": batch_id,
            "analysis_id": analysis_id,
            "decision_id": decision_id,
            "purpose_code": purpose_code,
            "purpose_detail": purpose_detail,
            "recipient_class": recipient_class,
            "recipients": recipients,
            "allowed_statements": statements,
            "effective_at": effective_at,
            "expires_at": expires_at,
            "reveal_paths": reveal_paths,
            "redact_paths": redact_paths,
        }
        fingerprint = scope_fingerprint(scope)
        payload = {
            "schema": DISCLOSURE_SCHEMA,
            "package_id": package_id,
            "issued_at": self._now(),
            "anchors": anchors,
            "content": visible,
            "field_manifest": manifest,
            "scope_fingerprint": fingerprint,
        }
        signature = sign_payload(payload, secret, key_id, 1)
        envelope = {"payload": payload, "signature": signature}
        envelope_text = canonical_json(envelope)

        tokens: list[dict[str, str]] = []
        with transaction(
            self.connection, immediate=True
        ):
            try:
                self.connection.execute(
                    "INSERT INTO disclosure_packages("
                    "package_id,batch_id,analysis_id,decision_id,purpose_code,purpose_detail,recipient_class,"
                    "recipients_json,allowed_statements_json,field_policy_json,jurisdictions_allowed_json,"
                    "effective_at,expires_at,retain_until,scope_fingerprint,package_sha256,envelope_json,"
                    "sign_key_id,sign_key_seq,signature,created_by,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        package_id, batch_id, analysis_id, decision_id, purpose_code, purpose_detail,
                        recipient_class, canonical_json(recipients), canonical_json(statements),
                        canonical_json({"reveal_paths": list(reveal_paths), "redact_paths": list(redact_paths)}),
                        canonical_json(jurisdictions), effective_at, expires_at, retain_until, fingerprint,
                        signature["digest"], envelope_text, key_id, 1, signature["value"], actor_id, self._now(),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValidationFailed("披露包编号冲突") from exc
            for item in recipients:
                token = base64.urlsafe_b64encode(os.urandom(24)).decode("ascii")
                self.connection.execute(
                    "INSERT INTO disclosure_recipients(package_id,recipient_id,name,jurisdiction,token_sha256) "
                    "VALUES(?,?,?,?,?)",
                    (package_id, item["recipient_id"], item["name"], item["jurisdiction"], hash_token(token)),
                )
                tokens.append({"recipient_id": item["recipient_id"], "token": token})
            self._audit("disclosure_package", package_id, "disclosure.issued", actor_id, {
                "batch_id": batch_id,
                "analysis_id": analysis_id,
                "decision_id": decision_id,
                "recipient_class": recipient_class,
                "purpose_code": purpose_code,
                "scope_fingerprint": fingerprint,
                "package_sha256": signature["digest"],
                "fields_revealed": list(reveal_paths),
                "expires_at": expires_at,
                "sign_key_id": key_id,
            })
        return {
            "package_id": package_id,
            "package_sha256": signature["digest"],
            "scope_fingerprint": fingerprint,
            "sign_key_id": key_id,
            "deliveries": tokens,
        }

    def _package_row(self, package_id: str):
        row = self.connection.execute(
            "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
        ).fetchone()
        if row is None:
            raise NotFound("披露包不存在")
        return row

    def _record_access(
        self,
        package_id: str,
        attempt_id: str,
        requested_by: str,
        recipient_id: str | None,
        jurisdiction: str | None,
        decision: str,
        deny_reason: str | None,
        fields_seen: list[str] | None,
        digest: str | None,
    ) -> None:
        self.connection.execute(
            "INSERT INTO disclosure_accesses("
            "package_id,attempt_id,requested_by,recipient_id,jurisdiction,decision,deny_reason,"
            "fields_seen_json,digest_sha256,attempted_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                package_id, attempt_id, requested_by, recipient_id, jurisdiction, decision, deny_reason,
                None if fields_seen is None else canonical_json(fields_seen), digest, self._now(),
            ),
        )

    def read_disclosure_package(
        self,
        package_id: str,
        recipient_id: str,
        token: str,
        jurisdiction: str,
        attempt_id: str,
    ) -> dict[str, Any]:
        """接收主体凭投递令牌读取冻结披露包；任何拒绝都留下访问事实。"""

        if not attempt_id.strip():
            raise ValidationFailed("attempt_id 不能为空")
        row = self._package_row(package_id)

        now = self._now()

        def deny(reason: str) -> Forbidden:
            self._record_access(
                package_id, attempt_id, f"recipient:{recipient_id}", recipient_id, jurisdiction,
                "denied", reason, None, None,
            )
            self._audit("disclosure_package", package_id, "disclosure.access_denied", f"recipient:{recipient_id}", {
                "attempt_id": attempt_id, "jurisdiction": jurisdiction, "reason": reason,
            })
            return Forbidden(f"披露包不可读: {reason}")

        def deny_auth() -> Forbidden:
            # 认证可能先于幂等记录发生：台账按 attempt_id 保持一行，重复探测只在审计流水中留痕。
            self.connection.execute(
                "INSERT OR IGNORE INTO disclosure_accesses("
                "package_id,attempt_id,requested_by,recipient_id,jurisdiction,decision,deny_reason,"
                "fields_seen_json,digest_sha256,attempted_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    package_id, attempt_id, f"recipient:{recipient_id}", recipient_id, jurisdiction,
                    "denied", "authentication_failed", None, None, self._now(),
                ),
            )
            self._audit("disclosure_package", package_id, "disclosure.access_denied", f"recipient:{recipient_id}", {
                "attempt_id": attempt_id, "jurisdiction": jurisdiction, "reason": "authentication_failed",
            })
            return Forbidden("披露包不可读: authentication_failed")

        # 认证先于一切：幂等重放也必须持有有效投递令牌，避免 attempt_id 被当作访问凭证。
        recipient = self.connection.execute(
            "SELECT token_sha256 FROM disclosure_recipients WHERE package_id=? AND recipient_id=?",
            (package_id, recipient_id),
        ).fetchone()
        if recipient is None or not hmac.compare_digest(recipient["token_sha256"], hash_token(token)):
            with transaction(self.connection, immediate=True):
                exc = deny_auth()
            raise exc

        prior = self.connection.execute(
            "SELECT decision,deny_reason FROM disclosure_accesses WHERE package_id=? AND attempt_id=?",
            (package_id, attempt_id),
        ).fetchone()
        if prior is not None:
            # 同一 attempt_id 的重试只能回放既有结论：被拒保持被拒，已交付回放同一冻结字节，
            # 绝不借重试重新评估条件或扩大范围。
            if prior["decision"] != "delivered":
                raise Forbidden(f"该请求曾被拒绝: {prior['deny_reason']}")
            return json.loads(row["envelope_json"])

        if row["state"] != "active":
            with transaction(self.connection, immediate=True):
                exc = deny("revoked")
            raise exc
        if now < row["effective_at"]:
            with transaction(self.connection, immediate=True):
                exc = deny("not_yet_effective")
            raise exc
        if now >= row["expires_at"]:
            with transaction(self.connection, immediate=True):
                exc = deny("expired")
            raise exc
        allowed_jurisdictions = set(json.loads(row["jurisdictions_allowed_json"]))
        if jurisdiction not in allowed_jurisdictions:
            with transaction(self.connection, immediate=True):
                exc = deny("jurisdiction_not_allowed")
            raise exc
        # 项目决定失效（被取代、批次修订变化）必须阻止后续读取。
        latest = self.connection.execute(
            "SELECT b.revision AS batch_revision,b.state AS batch_state,d.decision_id AS latest_decision "
            "FROM batches b LEFT JOIN decisions d ON d.batch_id=b.batch_id "
            "WHERE b.batch_id=?", (row["batch_id"],)
        ).fetchone()
        if (
            latest["batch_state"] != "decided"
            or latest["batch_revision"] != json.loads(row["envelope_json"])["payload"]["anchors"]["batch_revision"]
            or latest["latest_decision"] != row["decision_id"]
        ):
            with transaction(self.connection, immediate=True):
                exc = deny("decision_no_longer_effective")
            raise exc

        envelope = json.loads(row["envelope_json"])
        fields_seen = [
            entry["path"]
            for entry in envelope["payload"]["field_manifest"]
            if entry["status"] == "revealed"
        ]
        with transaction(
            self.connection, immediate=True
        ):
            self._record_access(
                package_id, attempt_id, f"recipient:{recipient_id}", recipient_id, jurisdiction,
                "delivered", None, fields_seen, row["package_sha256"],
            )
            self._audit("disclosure_package", package_id, "disclosure.access_delivered", f"recipient:{recipient_id}", {
                "attempt_id": attempt_id,
                "jurisdiction": jurisdiction,
                "fields_seen": fields_seen,
                "package_sha256": row["package_sha256"],
            })
        return envelope

    def revoke_disclosure_package(self, actor_id: str, package_id: str, reason: str) -> dict[str, Any]:
        self._require(actor_id, "disclosure.manage")
        if not reason.strip():
            raise ValidationFailed("撤回原因不能为空")
        row = self._package_row(package_id)
        if row["state"] != "active":
            raise InvalidState("披露包已撤回")
        with transaction(
            self.connection, immediate=True
        ):
            cursor = self.connection.execute(
                "UPDATE disclosure_packages SET state='revoked',revocation_reason=?,revoked_by=?,revoked_at=? "
                "WHERE package_id=? AND state='active'",
                (reason.strip(), actor_id, self._now(), package_id),
            )
            if cursor.rowcount != 1:
                raise InvalidState("披露包状态已变化")
            self._audit("disclosure_package", package_id, "disclosure.revoked", actor_id, {
                "reason": reason.strip(),
                "scope_fingerprint": row["scope_fingerprint"],
            })
        return {"package_id": package_id, "state": "revoked"}

    def restrict_disclosure_jurisdictions(
        self, actor_id: str, package_id: str, jurisdictions: list[str]
    ) -> dict[str, Any]:
        """辖区限制只能收窄、不能扩大，避免绕过已冻结范围。"""

        self._require(actor_id, "disclosure.manage")
        if not isinstance(jurisdictions, list) or not jurisdictions or any(
            not isinstance(item, str) or not item.strip() for item in jurisdictions
        ):
            raise ValidationFailed("jurisdictions 必须是非空辖区代码数组")
        new_set = {item.strip() for item in jurisdictions}
        row = self._package_row(package_id)
        if row["state"] != "active":
            raise InvalidState("披露包已撤回")
        current = set(json.loads(row["jurisdictions_allowed_json"]))
        if not new_set <= current or new_set == current:
            raise ValidationFailed("辖区限制只能在原授权范围内收窄")
        with transaction(
            self.connection, immediate=True
        ):
            self.connection.execute(
                "UPDATE disclosure_packages SET jurisdictions_allowed_json=? WHERE package_id=?",
                (canonical_json(sorted(new_set)), package_id),
            )
            self._audit("disclosure_package", package_id, "disclosure.jurisdictions_restricted", actor_id, {
                "removed": sorted(current - new_set),
                "remaining": sorted(new_set),
            })
        return {"package_id": package_id, "jurisdictions": sorted(new_set)}

    def resign_disclosure_package(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """用当前启用密钥重签：载荷字节与范围指纹必须保持不变。"""

        self._require(actor_id, "disclosure.manage")
        row = self._package_row(package_id)
        if row["state"] != "active":
            raise InvalidState("披露包已撤回，不能重签")
        key_id, secret = self._active_signing_key()
        if key_id == row["sign_key_id"]:
            raise InvalidState("当前启用密钥与原签名相同，请先轮换密钥再重签")
        envelope = json.loads(row["envelope_json"])
        before_payload = canonical_json(envelope["payload"])
        before_fingerprint = envelope["payload"]["scope_fingerprint"]
        new_seq = row["sign_key_seq"] + 1
        signature = sign_payload(envelope["payload"], secret, key_id, new_seq)
        if hashlib.sha256(before_payload.encode("utf-8")).hexdigest() != row["package_sha256"]:
            raise InvalidState("冻结载荷与登记摘要不一致，拒绝重签")
        if signature["digest"] != row["package_sha256"] or before_fingerprint != row["scope_fingerprint"]:
            raise InvalidState("重签导致范围或内容变化，拒绝写入")
        envelope["signature"] = signature
        with transaction(
            self.connection, immediate=True
        ):
            self.connection.execute(
                "UPDATE disclosure_packages SET sign_key_id=?,sign_key_seq=?,signature=?,envelope_json=? "
                "WHERE package_id=?",
                (key_id, new_seq, signature["value"], canonical_json(envelope), package_id),
            )
            self._audit("disclosure_package", package_id, "disclosure.resigned", actor_id, {
                "old_key_id": row["sign_key_id"],
                "new_key_id": key_id,
                "key_seq": new_seq,
                "scope_fingerprint": before_fingerprint,
                "package_sha256": row["package_sha256"],
            })
        return {
            "package_id": package_id,
            "package_sha256": row["package_sha256"],
            "scope_fingerprint": before_fingerprint,
            "sign_key_id": key_id,
            "sign_key_seq": new_seq,
        }

    def verify_disclosure_package(self, package_id: str) -> dict[str, Any]:
        """公开的来源校验：不返回内容，只证明冻结字节、签名与当前效力状态。"""

        row = self._package_row(package_id)
        envelope = json.loads(row["envelope_json"])
        payload_text = canonical_json(envelope["payload"])
        digest_ok = hashlib.sha256(payload_text.encode("utf-8")).hexdigest() == row["package_sha256"]
        try:
            secret = self._signing_key(envelope["signature"]["key_id"])
            expected = hmac.new(
                secret, row["package_sha256"].encode("ascii"), hashlib.sha256
            ).hexdigest()
            signature_ok = hmac.compare_digest(expected, envelope["signature"]["value"])
        except InvalidState:
            signature_ok = False
        now = self._now()
        latest = self.connection.execute(
            "SELECT b.revision AS batch_revision,b.state AS batch_state,d.decision_id AS latest_decision "
            "FROM batches b LEFT JOIN decisions d ON d.batch_id=b.batch_id WHERE b.batch_id=?",
            (row["batch_id"],),
        ).fetchone()
        decision_effective = (
            latest["batch_state"] == "decided"
            and latest["batch_revision"] == envelope["payload"]["anchors"]["batch_revision"]
            and latest["latest_decision"] == row["decision_id"]
        )
        return {
            "package_id": package_id,
            "package_sha256": row["package_sha256"],
            "digest_valid": digest_ok,
            "signature_valid": digest_ok and signature_ok,
            "sign_key_id": envelope["signature"]["key_id"],
            "sign_key_seq": envelope["signature"]["key_seq"],
            "state": row["state"],
            "effective_at": row["effective_at"],
            "expires_at": row["expires_at"],
            "within_validity": row["effective_at"] <= now < row["expires_at"],
            "decision_effective": decision_effective,
            "jurisdictions_active": json.loads(row["jurisdictions_allowed_json"]),
            "scope_fingerprint": row["scope_fingerprint"],
        }

    def verify_disclosure_redactions(self, actor_id: str, package_id: str) -> dict[str, Any]:
        """合规复核：用签发时密钥重算全部遮蔽承诺，验证与原证据锚点的关联。"""

        self._require(actor_id, "disclosure.ledger.read")
        row = self._package_row(package_id)
        envelope = json.loads(row["envelope_json"])
        payload = envelope["payload"]
        key_id = envelope["signature"]["key_id"]
        secret = self._signing_key(key_id)
        policy = json.loads(row["field_policy_json"])

        batch = self.get_batch(row["batch_id"])
        analysis_row = self.connection.execute(
            "SELECT * FROM analyses WHERE analysis_id=?", (row["analysis_id"],)
        ).fetchone()
        decision_row = self.connection.execute(
            "SELECT * FROM decisions WHERE decision_id=?", (row["decision_id"],)
        ).fetchone()
        ev_row = self.connection.execute(
            "SELECT * FROM evidence_revisions WHERE evidence_revision_id=?", (batch["evidence_revision_id"],)
        ).fetchone()
        program_row = self.connection.execute(
            "SELECT * FROM cooperation_programs WHERE program_id=?", (ev_row["program_id"],)
        ).fetchone()
        protocol, protocol_digest = self._protocol(batch["protocol_id"], batch["protocol_version"])

        content, anchors = self._disclosure_material(
            program_row, ev_row, batch, protocol, protocol_digest, analysis_row,
            json.loads(analysis_row["result_json"]), decision_row,
            row["purpose_code"], row["purpose_detail"], row["recipient_class"],
            json.loads(row["recipients_json"]), json.loads(row["allowed_statements_json"]),
            payload["content"]["jurisdictions_at_issuance"],
            row["effective_at"], row["expires_at"],
        )
        rebuilt_visible, rebuilt_manifest = redact_content(
            content, tuple(policy["reveal_paths"]), tuple(policy["redact_paths"]), secret
        )
        stored_manifest = {entry["path"]: entry for entry in payload["field_manifest"]}
        mismatches: list[str] = []
        for entry in rebuilt_manifest:
            stored = stored_manifest.get(entry["path"])
            if stored is None or stored["status"] != entry["status"]:
                mismatches.append(entry["path"])
                continue
            if entry["status"] != "revealed" and stored.get("commitment") != entry["commitment"]:
                mismatches.append(entry["path"])
        frozen_content_matches = canonical_json(rebuilt_visible) == canonical_json(payload["content"])
        anchors_match = anchors == payload["anchors"]
        return {
            "package_id": package_id,
            "sign_key_id": key_id,
            "redacted_fields": [
                entry["path"] for entry in rebuilt_manifest if entry["status"] != "revealed"
            ],
            "commitments_valid": not mismatches,
            "mismatched_fields": mismatches,
            "frozen_content_matches_source": frozen_content_matches,
            "anchors_valid": anchors_match,
            "analysis_input_sha256": anchors["analysis_input_sha256"],
            "evidence_sha256": anchors["evidence_sha256"],
        }

    def disclosure_ledger(self, actor_id: str, package_id: str | None = None) -> dict[str, Any]:
        """合规台账：回答谁在何时因何目的看到哪些内容，以及拒绝、重试、撤回、重签。"""

        self._require(actor_id, "disclosure.ledger.read")
        if package_id is not None:
            rows = self.connection.execute(
                "SELECT * FROM disclosure_packages WHERE package_id=?", (package_id,)
            ).fetchall()
            if not rows:
                raise NotFound("披露包不存在")
        else:
            rows = self.connection.execute("SELECT * FROM disclosure_packages ORDER BY created_at,package_id").fetchall()
        packages: list[dict[str, Any]] = []
        for row in rows:
            envelope = json.loads(row["envelope_json"])
            accesses = self.connection.execute(
                "SELECT * FROM disclosure_accesses WHERE package_id=? ORDER BY access_id", (row["package_id"],)
            ).fetchall()
            recomputed = scope_fingerprint({
                "batch_id": row["batch_id"],
                "analysis_id": row["analysis_id"],
                "decision_id": row["decision_id"],
                "purpose_code": row["purpose_code"],
                "purpose_detail": row["purpose_detail"],
                "recipient_class": row["recipient_class"],
                "recipients": json.loads(row["recipients_json"]),
                "allowed_statements": json.loads(row["allowed_statements_json"]),
                "effective_at": row["effective_at"],
                "expires_at": row["expires_at"],
                "reveal_paths": json.loads(row["field_policy_json"])["reveal_paths"],
                "redact_paths": json.loads(row["field_policy_json"])["redact_paths"],
            })
            delivered = [item for item in accesses if item["decision"] == "delivered"]
            denied = [item for item in accesses if item["decision"] == "denied"]
            packages.append({
                "package_id": row["package_id"],
                "batch_id": row["batch_id"],
                "analysis_id": row["analysis_id"],
                "decision_id": row["decision_id"],
                "purpose_code": row["purpose_code"],
                "purpose_detail": row["purpose_detail"],
                "recipient_class": row["recipient_class"],
                "recipients": json.loads(row["recipients_json"]),
                "allowed_statements": json.loads(row["allowed_statements_json"]),
                "field_policy": json.loads(row["field_policy_json"]),
                "fields_revealed": [
                    entry["path"]
                    for entry in envelope["payload"]["field_manifest"]
                    if entry["status"] == "revealed"
                ],
                "jurisdictions_at_issuance": envelope["payload"]["content"]["jurisdictions_at_issuance"],
                "jurisdictions_active": json.loads(row["jurisdictions_allowed_json"]),
                "effective_at": row["effective_at"],
                "expires_at": row["expires_at"],
                "retain_until": row["retain_until"],
                "state": row["state"],
                "revocation_reason": row["revocation_reason"],
                "package_sha256": row["package_sha256"],
                "scope_fingerprint": row["scope_fingerprint"],
                "scope_unchanged": recomputed == row["scope_fingerprint"],
                "sign_key_id": row["sign_key_id"],
                "sign_key_seq": row["sign_key_seq"],
                "created_by": row["created_by"],
                "created_at": row["created_at"],
                "delivered_count": len(delivered),
                "denied_count": len(denied),
                "deny_reasons": sorted({item["deny_reason"] for item in denied}),
                "accesses": [
                    {
                        "attempt_id": item["attempt_id"],
                        "requested_by": item["requested_by"],
                        "recipient_id": item["recipient_id"],
                        "jurisdiction": item["jurisdiction"],
                        "decision": item["decision"],
                        "deny_reason": item["deny_reason"],
                        "fields_seen": None
                        if item["fields_seen_json"] is None
                        else json.loads(item["fields_seen_json"]),
                        "digest_sha256": item["digest_sha256"],
                        "attempted_at": item["attempted_at"],
                    }
                    for item in accesses
                ],
            })
        return {"packages": packages}
