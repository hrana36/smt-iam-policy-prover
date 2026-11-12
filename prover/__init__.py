"""
SMT IAM Policy Prover
Automated Formal Verification and Reachability Analysis of Multi-Cloud Access Control Policies
using the Microsoft Z3 SMT Theorem Prover.
"""

from .ast_models import IAMPolicy, Statement, Effect, Condition
from .smt_encoder import SMTEncoder
from .reachability import ReachabilityProver, ReachabilityResult
from .equivalence import EquivalenceProver, EquivalenceResult
from .redundancy import RedundancyAnalyzer, RedundancyReport

__version__ = "1.0.0"
__author__ = "Md Habibur Rahaman Rana"

__all__ = [
    "IAMPolicy",
    "Statement",
    "Effect",
    "Condition",
    "SMTEncoder",
    "ReachabilityProver",
    "ReachabilityResult",
    "EquivalenceProver",
    "EquivalenceResult",
    "RedundancyAnalyzer",
    "RedundancyReport",
]
