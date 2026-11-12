"""
prover/redundancy.py
Formal Redundancy and Shadowed Statement Analyzer using Z3.
Detects dead rules, unreachable allow clauses, and statements shadowed by explicit denies.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import time
import z3
from .ast_models import IAMPolicy, Statement
from .smt_encoder import SMTEncoder


@dataclass
class RedundancyReport:
    """Report detailing redundant, dead, or shadowed statements."""
    policy_name: str
    total_statements: int
    shadowed_statements: List[Dict[str, Any]]
    analysis_time_ms: float = 0.0

    @property
    def has_redundancies(self) -> bool:
        return len(self.shadowed_statements) > 0


class RedundancyAnalyzer:
    r"""
    Identifies statements s_i that have zero impact on the policy's decision boundary:
    forall R. Authorize(P, R) <=> Authorize(P \ {s_i}, R)
    """

    def __init__(self, encoder: Optional[SMTEncoder] = None):
        self.encoder = encoder or SMTEncoder()

    def analyze(self, policy: IAMPolicy) -> RedundancyReport:
        start = time.perf_counter()
        shadowed: List[Dict[str, Any]] = []

        if len(policy.statements) <= 1:
            return RedundancyReport(
                policy_name=policy.name,
                total_statements=len(policy.statements),
                shadowed_statements=[],
                analysis_time_ms=0.0,
            )

        full_formula = self.encoder.encode_policy(policy)

        for i, stmt in enumerate(policy.statements):
            # Create reduced policy without statement i
            reduced_stmts = [s for j, s in enumerate(policy.statements) if j != i]
            reduced_policy = IAMPolicy(name=f"{policy.name}_minus_{i}", statements=reduced_stmts)
            reduced_formula = self.encoder.encode_policy(reduced_policy)

            # Check if there exists ANY request where full_formula != reduced_formula
            solver = z3.Solver()
            solver.add(full_formula != reduced_formula)

            if solver.check() == z3.unsat:
                # Removing statement i NEVER changes any authorization decision!
                shadowed.append({
                    "statement_index": i,
                    "sid": stmt.sid,
                    "effect": stmt.effect.value,
                    "actions": stmt.actions,
                    "resources": stmt.resources,
                    "reason": "SHADOWED_OR_DEAD_STATEMENT (Removing this statement does not alter any decision)",
                })

        elapsed_ms = (time.perf_counter() - start) * 1000.0

        return RedundancyReport(
            policy_name=policy.name,
            total_statements=len(policy.statements),
            shadowed_statements=shadowed,
            analysis_time_ms=round(elapsed_ms, 3),
        )
