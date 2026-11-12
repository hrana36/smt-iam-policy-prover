"""
prover/equivalence.py
Semantic Equivalence and Policy Subsumption (Containment) Prover.
Mathematically proves whether two cloud IAM policies grant identical access sets.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, Optional
import time
import z3
from .ast_models import IAMPolicy
from .smt_encoder import SMTEncoder


@dataclass
class EquivalenceResult:
    """Outcome of policy equivalence or subsumption verification."""
    are_equivalent: bool
    subsumption: Optional[str] = None  # E.g. "P1_SUBSET_OF_P2", "P2_SUBSET_OF_P1", "NONE"
    counterexample: Optional[Dict[str, Any]] = None
    solver_time_ms: float = 0.0
    proof_status: str = "UNKNOWN"


class EquivalenceProver:
    """
    Proves mathematical equivalence and containment between two IAM policies:
    P1 === P2  <=>  forall R. Authorize(P1, R) <=> Authorize(P2, R)
    """

    def __init__(self, encoder: Optional[SMTEncoder] = None):
        self.encoder = encoder or SMTEncoder()

    def prove_equivalence(self, policy_1: IAMPolicy, policy_2: IAMPolicy) -> EquivalenceResult:
        """
        Proves whether Policy 1 and Policy 2 are semantically identical.
        Checks satisfiability of: Authorize(P1, R) != Authorize(P2, R)
        """
        start = time.perf_counter()
        solver = z3.Solver()

        formula_1 = self.encoder.encode_policy(policy_1)
        formula_2 = self.encoder.encode_policy(policy_2)

        # Discrepancy constraint: One allows while the other denies
        discrepancy = formula_1 != formula_2
        solver.add(discrepancy)

        check_res = solver.check()
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        if check_res == z3.unsat:
            # No discrepancy exists under ANY possible input!
            return EquivalenceResult(
                are_equivalent=True,
                subsumption="MUTUALLY_EQUIVALENT",
                counterexample=None,
                solver_time_ms=round(elapsed_ms, 3),
                proof_status="PROVEN_EQUIVALENT (UNSAT_DISCREPANCY)",
            )
        elif check_res == z3.sat:
            # Satisfiable -> Found counterexample request where behaviors diverge!
            m = solver.model()
            counterexample = {
                "action": str(m.eval(self.encoder.var_action, model_completion=True)),
                "resource": str(m.eval(self.encoder.var_resource, model_completion=True)),
                "principal": str(m.eval(self.encoder.var_principal, model_completion=True)),
                "mfa_present": bool(m.eval(self.encoder.var_mfa_present, model_completion=True)),
                "p1_decision": bool(m.eval(formula_1, model_completion=True)),
                "p2_decision": bool(m.eval(formula_2, model_completion=True)),
            }
            # Check one-way subsumption
            subsumption = self._check_subsumption_direction(policy_1, policy_2)
            return EquivalenceResult(
                are_equivalent=False,
                subsumption=subsumption,
                counterexample=counterexample,
                solver_time_ms=round(elapsed_ms, 3),
                proof_status="DIVERGENT (COUNTEREXAMPLE_FOUND)",
            )
        else:
            return EquivalenceResult(
                are_equivalent=False,
                solver_time_ms=round(elapsed_ms, 3),
                proof_status="UNKNOWN / TIMEOUT",
            )

    def _check_subsumption_direction(self, p1: IAMPolicy, p2: IAMPolicy) -> str:
        """Determines whether P1 is a strict subset of P2 or vice-versa."""
        f1 = self.encoder.encode_policy(p1)
        f2 = self.encoder.encode_policy(p2)

        # Check P1 -> P2 (Is P1 subset of P2?)
        s1 = z3.Solver()
        s1.add(z3.And(f1, z3.Not(f2)))
        p1_subset = (s1.check() == z3.unsat)

        # Check P2 -> P1 (Is P2 subset of P1?)
        s2 = z3.Solver()
        s2.add(z3.And(f2, z3.Not(f1)))
        p2_subset = (s2.check() == z3.unsat)

        if p1_subset and not p2_subset:
            return "P1_STRICT_SUBSET_OF_P2"
        elif p2_subset and not p1_subset:
            return "P2_STRICT_SUBSET_OF_P1"
        return "DISJOINT_OR_INCOMPARABLE"
