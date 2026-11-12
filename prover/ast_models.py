"""
prover/ast_models.py
Abstract Syntax Tree (AST) representations for Multi-Cloud IAM Policies.
Supports AWS IAM, Azure RBAC, and declarative JSON access control specifications.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
import json


class Effect(str, Enum):
    ALLOW = "Allow"
    DENY = "Deny"


@dataclass
class Condition:
    """Represents an IAM condition block: Operator -> Key -> Values."""
    operator: str
    key: str
    values: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {self.operator: {self.key: self.values}}


@dataclass
class Statement:
    """Represents a single IAM policy statement."""
    sid: str
    effect: Effect
    actions: List[str] = field(default_factory=list)
    not_actions: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    not_resources: List[str] = field(default_factory=list)
    principals: List[str] = field(default_factory=list)
    not_principals: List[str] = field(default_factory=list)
    conditions: List[Condition] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], default_sid: str = "Stmt") -> Statement:
        sid = data.get("Sid", default_sid)
        effect_str = data.get("Effect", "Allow")
        effect = Effect.DENY if effect_str.lower() == "deny" else Effect.ALLOW

        def _to_list(val: Any) -> List[str]:
            if val is None:
                return []
            if isinstance(val, list):
                return [str(x) for x in val]
            if isinstance(val, dict):
                # E.g. Principal: {"AWS": "arn:aws:iam::..."}
                res = []
                for k, v in val.items():
                    if isinstance(v, list):
                        res.extend(v)
                    else:
                        res.append(str(v))
                return res
            return [str(val)]

        actions = _to_list(data.get("Action"))
        not_actions = _to_list(data.get("NotAction"))
        resources = _to_list(data.get("Resource"))
        not_resources = _to_list(data.get("NotResource"))
        principals = _to_list(data.get("Principal"))
        not_principals = _to_list(data.get("NotPrincipal"))

        # Parse condition block
        conditions = []
        raw_cond = data.get("Condition", {})
        if isinstance(raw_cond, dict):
            for op, key_dict in raw_cond.items():
                if isinstance(key_dict, dict):
                    for k, vals in key_dict.items():
                        c_vals = _to_list(vals)
                        conditions.append(Condition(operator=op, key=k, values=c_vals))

        return cls(
            sid=sid,
            effect=effect,
            actions=actions,
            not_actions=not_actions,
            resources=resources,
            not_resources=not_resources,
            principals=principals,
            not_principals=not_principals,
            conditions=conditions,
        )


@dataclass
class IAMPolicy:
    """Represents a complete Multi-Cloud IAM policy document."""
    name: str
    version: str = "2012-10-17"
    statements: List[Statement] = field(default_factory=list)

    @classmethod
    def from_json(cls, source: Union[str, Dict[str, Any]], name: str = "UnnamedPolicy") -> IAMPolicy:
        if isinstance(source, str):
            data = json.loads(source)
        else:
            data = source

        version = data.get("Version", "2012-10-17")
        raw_stmts = data.get("Statement", [])
        if isinstance(raw_stmts, dict):
            raw_stmts = [raw_stmts]

        statements = [
            Statement.from_dict(s, default_sid=f"Stmt_{i+1}")
            for i, s in enumerate(raw_stmts)
        ]

        return cls(name=name, version=version, statements=statements)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Version": self.version,
            "Statement": [
                {
                    "Sid": s.sid,
                    "Effect": s.effect.value,
                    "Action": s.actions if s.actions else None,
                    "Resource": s.resources if s.resources else None,
                }
                for s in self.statements
            ],
        }
