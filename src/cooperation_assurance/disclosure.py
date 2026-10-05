"""分级披露：冻结结论文档、遮蔽敏感字段并签名来源。

本模块只包含纯函数，便于离线重放与单元测试；持久化和门控在
``service.AssuranceService`` 中完成。

设计要点：

* 披露包的 ``manifest`` 固定使用目的、接收主体、允许声明、遮蔽规则、
  数据驻留区域和有效期；``document`` 是按遮蔽规则处理后的项目结论；
* 被遮蔽的节点替换为 ``{"__redacted__": true, "sha256": ...}``，摘要是
  对该节点原始规范化内容计算的 SHA-256，因此声明与原证据之间仍保留
  可验证关联，但包内不出现可访问未授权记录的内部标识或链接；
* ``manifest.anchors`` 仅放原始证据/分析/决定的内容摘要，不放内部行号
  或接口地址，接收方无法沿引用回溯未授权记录；
* ``scope_sha256`` 只覆盖授权范围（目的、接收主体、允许声明、遮蔽规则、
  驻留区域），重签续期不改变范围指纹，合规台账据此判断是否扩大范围；
* 来源签名采用 HMAC-SHA256，签名输入是去掉 attestation 段的规范化包体，
  ``package_sha256`` 独立于签名密钥，任何持有包体的人都能校验内容冻结。
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Any, Mapping, Sequence

from .clock import isoformat
from .jsonio import canonical_json, content_digest


DISCLOSURE_SCHEMA = "cooperation-assurance-disclosure/1"
SIGNING_ALGORITHM = "HMAC-SHA256"
REDACTION_MARKER = "__redacted__"

RECIPIENT_KINDS = ("investor", "regulator", "assessor")

# 责任方可以选择遮蔽的字段目录（JSON 指针）。遮蔽规则只能从此目录选择，
# 拼写错误会被拒绝，避免“以为遮住、实际外泄”。
REDACTABLE_PATHS: frozenset[str] = frozenset({
    "/program/program_id",
    "/program/program_name",
    "/program/lead_organization",
    "/evidence/revision",
    "/evidence/content_sha256",
    "/protocol/protocol_id",
    "/protocol/sha256",
    "/analysis/strata",
    "/analysis/excluded_count",
    "/analysis/aggregate",
    "/decision/decision",
    "/decision/reason",
})

# 三类接收主体的默认分级画像。责任方仍可在签发时显式给出规则集合。
REDACTION_PROFILES: Mapping[str, tuple[str, ...]] = {
    # 境外投资人：只看项目总体结论与准入决定，商业敏感的分层细节、
    # 内部编号、决定理由均遮蔽。
    "investor": (
        "/program/program_id",
        "/program/lead_organization",
        "/evidence/revision",
        "/protocol/protocol_id",
        "/analysis/strata",
        "/analysis/excluded_count",
        "/decision/reason",
    ),
    # 属地监管机构：看到完整结论、分层、排除数量与决定理由，驻留区域
    # 在签发时单独约束。
    "regulator": (),
    # 独立评估方：看到方法与分析细节（协议、分层、规则），但对项目商业
    # 身份和审批 deliberation 保持盲态。
    "assessor": (
        "/program/program_id",
        "/program/program_name",
        "/program/lead_organization",
        "/decision/reason",
    ),
}


class DisclosureError(ValueError):
    """披露请求不满足契约。"""


def generate_signing_key() -> str:
    return secrets.token_hex(32)


def parse_expires_at(value: str, *, now: datetime) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise DisclosureError("expires_at 必须是 ISO 8601 时间字符串")
    text = value.strip().replace("Z", "+00:00") if value.strip().endswith("Z") else value.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DisclosureError("expires_at 不是有效的 ISO 8601 时间") from exc
    if parsed.tzinfo is None:
        raise DisclosureError("expires_at 必须带时区")
    parsed = parsed.astimezone(now.tzinfo)
    if parsed <= now:
        raise DisclosureError("有效期限必须晚于当前时间")
    return parsed


def normalize_recipient(raw: Mapping[str, Any]) -> dict[str, str]:
    recipient_id = raw.get("id")
    kind = raw.get("kind")
    jurisdiction = raw.get("jurisdiction")
    if not isinstance(recipient_id, str) or not recipient_id.strip():
        raise DisclosureError("recipient.id 必须是非空字符串")
    if kind not in RECIPIENT_KINDS:
        raise DisclosureError(f"recipient.kind 必须是 {RECIPIENT_KINDS} 之一")
    if not isinstance(jurisdiction, str) or not jurisdiction.strip():
        raise DisclosureError("recipient.jurisdiction 必须是非空字符串")
    return {
        "id": recipient_id.strip(),
        "kind": kind,
        "jurisdiction": jurisdiction.strip().upper(),
    }


def normalize_statements(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise DisclosureError("allowed_statements 必须是字符串数组")
    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise DisclosureError("allowed_statements 不能含空值")
        normalized.append(item.strip())
    if not normalized:
        raise DisclosureError("allowed_statements 不能为空")
    if len(set(normalized)) != len(normalized):
        raise DisclosureError("allowed_statements 不能重复")
    return tuple(normalized)


def normalize_regions(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or not values:
        raise DisclosureError("data_regions 必须是非空字符串数组")
    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise DisclosureError("data_regions 不能含空值")
        normalized.append(item.strip().upper())
    if len(set(normalized)) != len(normalized):
        raise DisclosureError("data_regions 不能重复")
    return tuple(sorted(normalized))


def normalize_redaction_rules(values: Sequence[str], recipient_kind: str) -> tuple[str, ...]:
    if values is None:
        return tuple(sorted(REDACTION_PROFILES[recipient_kind]))
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise DisclosureError("redaction_rules 必须是字符串数组")
    rules = list(values)
    unknown = sorted(set(rules) - REDACTABLE_PATHS)
    if unknown:
        raise DisclosureError(f"遮蔽规则引用了不可遮蔽字段: {unknown}")
    if len(set(rules)) != len(rules):
        raise DisclosureError("redaction_rules 不能重复")
    return tuple(sorted(rules))


def build_conclusion_document(
    *,
    program: Mapping[str, Any],
    evidence: Mapping[str, Any],
    protocol: Mapping[str, Any],
    analysis_result: Mapping[str, Any],
    decision: Mapping[str, Any],
) -> dict[str, Any]:
    """从完整记录中抽取可披露的项目结论模板。

    模板中的每个叶子要么进入披露包，要么必须被显式遮蔽；服务层会校验
    红后文档中没有任何内部行号或接口引用。
    """

    return {
        "program": {
            "program_id": program["program_id"],
            "program_name": program["program_name"],
            "lead_organization": program["lead_organization"],
        },
        "evidence": {
            "revision": evidence["version"],
            "content_sha256": evidence["content_sha256"],
        },
        "protocol": {
            "protocol_id": protocol["protocol_id"],
            "version": protocol["version"],
            "sha256": protocol["sha256"],
        },
        "analysis": {
            "conclusion": analysis_result["conclusion"],
            "included_count": analysis_result["included_count"],
            "excluded_count": analysis_result["excluded_count"],
            "aggregate": analysis_result["aggregate"],
            "rules": analysis_result["rules"],
            "strata": analysis_result["strata"],
        },
        "decision": {
            "decision": decision["decision"],
            "reason": decision["reason"],
        },
    }


def _walk_pointer(document: Mapping[str, Any], pointer: str) -> tuple[dict[str, Any], str]:
    parts = [part for part in pointer.split("/") if part]
    if "/" + "/".join(parts) != pointer:
        raise DisclosureError(f"非法遮蔽路径: {pointer}")
    node: Any = document
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            raise DisclosureError(f"遮蔽路径不存在: {pointer}")
        node = node[part]
    last = parts[-1]
    if not isinstance(node, dict) or last not in node:
        raise DisclosureError(f"遮蔽路径不存在: {pointer}")
    return node, last


def apply_redactions(document: Mapping[str, Any], rules: Sequence[str]) -> dict[str, Any]:
    """返回遮蔽后的深拷贝；被遮蔽节点替换为摘要锚点。"""

    redacted = {
        "program": dict(document["program"]),
        "evidence": dict(document["evidence"]),
        "protocol": dict(document["protocol"]),
        "analysis": dict(document["analysis"]),
        "decision": dict(document["decision"]),
    }
    for pointer in rules:
        node, key = _walk_pointer(redacted, pointer)
        original = node[key]
        node[key] = {
            REDACTION_MARKER: True,
            "sha256": hashlib.sha256(canonical_json(original).encode("utf-8")).hexdigest(),
        }
    return redacted


def scope_fingerprint(
    *,
    purpose: str,
    recipient: Mapping[str, str],
    allowed_statements: Sequence[str],
    redaction_rules: Sequence[str],
    data_regions: Sequence[str],
) -> str:
    scope = {
        "purpose": purpose,
        "recipient": {
            "id": recipient["id"],
            "kind": recipient["kind"],
            "jurisdiction": recipient["jurisdiction"],
        },
        "allowed_statements": tuple(sorted(allowed_statements)),
        "redaction_rules": tuple(sorted(redaction_rules)),
        "data_regions": tuple(sorted(data_regions)),
    }
    return content_digest([scope])


def build_manifest(
    *,
    package_id: str,
    issued_at: datetime,
    expires_at: datetime,
    purpose: str,
    recipient: Mapping[str, str],
    allowed_statements: Sequence[str],
    redaction_rules: Sequence[str],
    data_regions: Sequence[str],
    anchors: Mapping[str, Any],
    document: Mapping[str, Any],
    scope_sha256: str,
) -> dict[str, Any]:
    return {
        "schema": DISCLOSURE_SCHEMA,
        "package_id": package_id,
        "issued_at": isoformat(issued_at),
        "expires_at": isoformat(expires_at),
        "purpose": purpose,
        "recipient": {
            "id": recipient["id"],
            "kind": recipient["kind"],
            "jurisdiction": recipient["jurisdiction"],
        },
        "allowed_statements": tuple(sorted(allowed_statements)),
        "redaction_rules": tuple(sorted(redaction_rules)),
        "data_regions": tuple(sorted(data_regions)),
        "anchors": {
            "batch_revision": anchors["batch_revision"],
            "evidence_sha256": anchors["evidence_sha256"],
            "protocol_sha256": anchors["protocol_sha256"],
            "input_sha256": anchors["input_sha256"],
            "result_sha256": anchors["result_sha256"],
            "decision_sha256": anchors["decision_sha256"],
        },
        "scope_sha256": scope_sha256,
        "document_sha256": hashlib.sha256(
            canonical_json(document).encode("utf-8")
        ).hexdigest(),
    }


def build_package(manifest: Mapping[str, Any], document: Mapping[str, Any]) -> dict[str, Any]:
    return {"manifest": dict(manifest), "document": dict(document)}


def package_digest(package: Mapping[str, Any]) -> str:
    return content_digest([package])


def sign_package(package: Mapping[str, Any], signing_key: str) -> str:
    return hmac.new(
        signing_key.encode("utf-8"),
        canonical_json(package).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(package: Mapping[str, Any], signature_sha256: str, signing_key: str) -> bool:
    return hmac.compare_digest(sign_package(package, signing_key), signature_sha256)


def envelope(package: Mapping[str, Any], signature_sha256: str) -> dict[str, Any]:
    """接收方拿到的完整信封：包体 + 来源证明。"""

    return {
        **package,
        "attestation": {
            "algorithm": SIGNING_ALGORITHM,
            "signature_sha256": signature_sha256,
            "package_sha256": package_digest(package),
        },
    }
