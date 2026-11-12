"""
prover/reachability.py
Formal Reachability and Privilege Escalation Prover using Z3 SMT Solver.
Proves whether an unauthorized principal can attain administrative actions or bypass security invariants.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import time
import z3
from .ast_models import IAMPolicy
from .smt_encoder import SMTEncoder


@dataclass
class ReachabilityResult:
    """The formal proof outcome produced by the SMT solver."""
    is_reachable: bool
    query_description: str
    counterexample: Optional[Dict[str, Any]] = None
    solver_time_ms: float = 0.0
    proof_status: str = "UNKNOWN"

    @property
    def is_safe(self) -> bool:
        """If target attack state is unreachable, the system is mathematically safe."""
        return not self.is_reachable


class ReachabilityProver:
    """
    Executes automated reachability queries against encoded IAM policy formulas.
    """

    def __init__(self, encoder: Optional[SMTEncoder] = None):
        self.encoder = encoder or SMTEncoder()

    def check_reachability(
        self,
        policy: IAMPolicy,
        target_action_pattern: Optional[str] = None,
        target_resource_pattern: Optional[str] = None,
        require_no_mfa: bool = False,
        query_description: str = "Generic Reachability Query",
    ) -> ReachabilityResult:
        """
        Queries: Exists R = (p, a, r, c) such that Authorize(policy, R) and TargetConditions(R) holds.
        """
        start = time.perf_counter()
        solver = z3.Solver()

        # 1. Add Policy Authorization Formula
        policy_formula = self.encoder.encode_policy(policy)
        solver.add(policy_formula)

        # 2. Add Target Query Constraints
        if target_action_pattern:
            action_clause = self.encoder._match_pattern(self.encoder.var_action, target_action_pattern)
            solver.add(action_clause)

        if target_resource_pattern:
            res_clause = self.encoder._match_pattern(self.encoder.var_resource, target_resource_pattern)
            solver.add(res_clause)

        if require_no_mfa:
            # Check if reachable WITHOUT Multi-Factor Authentication
            solver.add(z3.Not(self.encoder.var_mfa_present))

        # 3. Solve SMT satisfiability
        check_result = solver.check()
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if check_result == z3.sat:
            # Satisfiable -> Attack state is REACHABLE! Extract counterexample model.
            model = solver.model()
            counterexample = {
                "action": str(model.eval(self.encoder.var_action, model_completion=True)),
                "resource": str(model.eval(self.encoder.var_resource, model_completion=True)),
                "principal": str(model.eval(self.encoder.var_principal, model_completion=True)),
                "mfa_present": bool(model.eval(self.encoder.var_mfa_present, model_completion=True)),
            }
            return ReachabilityResult(
                is_reachable=True,
                query_description=query_description,
                counterexample=counterexample,
                solver_time_ms=round(elapsed_ms, 3),
                proof_status="SATISFIABLE (EXPLOIT_PATH_FOUND)",
            )
        elif check_result == z3.unsat:
            # Unsatisfiable -> Attack state is MATHEMATICALLY PROVEN UNREACHABLE!
            return ReachabilityResult(
                is_reachable=False,
                query_description=query_description,
                counterexample=None,
                solver_time_ms=round(elapsed_ms, 3),
                proof_status="UNSATISFIABLE (PROVEN_SAFE)",
            )
        else:
            return ReachabilityResult(
                is_reachable=False,
                query_description=query_description,
                solver_time_ms=round(elapsed_ms, 3),
                proof_status="UNKNOWN / TIMEOUT",
            )

    def check_admin_privilege_escalation(self, policy: IAMPolicy) -> ReachabilityResult:
        """
        Standardized security query: Can any request achieve full root/admin permissions (iam:* or *:*)?
        """
        return self.check_reachability(
            policy=policy,
            target_action_pattern="*",
            query_description="Root Administrative Privilege Escalation (*:*)",
        )

    def check_unauthenticated_bucket_access(self, policy: IAMPolicy) -> ReachabilityResult:
        """
        Standardized query: Can anonymous or unauthenticated principals access S3 objects?
        """
        return self.check_reachability(
            policy=policy,
            target_action_pattern="s3:GetObject",
            query_description="Unauthenticated S3 Data Access Reachability",
        )
