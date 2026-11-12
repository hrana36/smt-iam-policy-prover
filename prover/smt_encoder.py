"""
prover/smt_encoder.py
Translates IAM Policy AST into First-Order Logic (FOL) formulas using Microsoft Z3.
Formalizes IAM Evaluation Logic: Deny Precedence, Wildcard Matching, and Conditions.
"""

from __future__ import annotations
from typing import Dict, List, Optional, Tuple, Any
import z3
from .ast_models import IAMPolicy, Statement, Effect, Condition


class SMTEncoder:
    """
    Encodes IAM Access Control specifications into Z3 SMT constraints.
    Formalizes request context R = (principal, action, resource, conditions).
    """

    def __init__(self):
        # Universal Request Variables
        self.var_principal = z3.String("request_principal")
        self.var_action = z3.String("request_action")
        self.var_resource = z3.String("request_resource")
        self.var_mfa_present = z3.Bool("request_mfa_present")
        self.var_source_ip = z3.String("request_source_ip")

    def encode_policy(self, policy: IAMPolicy) -> z3.BoolRef:
        """
        Encodes a complete IAM policy into an authorization formula:
        Authorize(P, R) <=> IsAllow(P, R) and not IsDeny(P, R)
        """
        allow_clauses = []
        deny_clauses = []

        for stmt in policy.statements:
            stmt_formula = self.encode_statement(stmt)
            if stmt.effect == Effect.DENY:
                deny_clauses.append(stmt_formula)
            else:
                allow_clauses.append(stmt_formula)

        is_allow = z3.Or(allow_clauses) if allow_clauses else z3.BoolVal(False)
        is_deny = z3.Or(deny_clauses) if deny_clauses else z3.BoolVal(False)

        # Authorize: Explicit Allow AND NOT Explicit Deny
        return z3.And(is_allow, z3.Not(is_deny))

    def encode_statement(self, stmt: Statement) -> z3.BoolRef:
        """
        Encodes a single statement into a matching conjunction:
        Matches(s, R) = MatchesAction(s, a) and MatchesResource(s, r) and
                        MatchesPrincipal(s, p) and MatchesConditions(s, c)
        """
        clauses = []

        # 1. Action Matching
        if stmt.actions:
            action_matches = [self._match_pattern(self.var_action, act) for act in stmt.actions]
            clauses.append(z3.Or(action_matches))
        elif stmt.not_actions:
            not_act_matches = [self._match_pattern(self.var_action, act) for act in stmt.not_actions]
            clauses.append(z3.Not(z3.Or(not_act_matches)))

        # 2. Resource Matching
        if stmt.resources:
            res_matches = [self._match_pattern(self.var_resource, res) for res in stmt.resources]
            clauses.append(z3.Or(res_matches))
        elif stmt.not_resources:
            not_res_matches = [self._match_pattern(self.var_resource, res) for res in stmt.not_resources]
            clauses.append(z3.Not(z3.Or(not_res_matches)))

        # 3. Principal Matching
        if stmt.principals and "*" not in stmt.principals:
            p_matches = [self._match_pattern(self.var_principal, p) for p in stmt.principals]
            clauses.append(z3.Or(p_matches))
        elif stmt.not_principals:
            not_p_matches = [self._match_pattern(self.var_principal, p) for p in stmt.not_principals]
            clauses.append(z3.Not(z3.Or(not_p_matches)))

        # 4. Condition Matching
        for cond in stmt.conditions:
            cond_expr = self._encode_condition(cond)
            if cond_expr is not None:
                clauses.append(cond_expr)

        return z3.And(clauses) if clauses else z3.BoolVal(True)

    def _match_pattern(self, var: z3.SeqRef, pattern: str) -> z3.BoolRef:
        """
        Handles wildcard matching semantics:
        - '*' matches everything.
        - 'prefix*' matches prefix.
        - '*suffix' matches suffix.
        - 'literal' matches exact string.
        """
        pattern = pattern.strip()
        if pattern == "*":
            return z3.BoolVal(True)

        if pattern.endswith("*") and not pattern.startswith("*"):
            prefix = pattern[:-1]
            return z3.PrefixOf(z3.StringVal(prefix), var)

        if pattern.startswith("*") and not pattern.endswith("*"):
            suffix = pattern[1:]
            return z3.SuffixOf(z3.StringVal(suffix), var)

        if pattern.startswith("*") and pattern.endswith("*") and len(pattern) > 2:
            substr = pattern[1:-1]
            return z3.Contains(var, z3.StringVal(substr))

        # Exact match
        return var == z3.StringVal(pattern)

    def _encode_condition(self, cond: Condition) -> Optional[z3.BoolRef]:
        """Encodes conditional clauses such as aws:MultiFactorAuthPresent or aws:SourceIP."""
        op = cond.operator.lower()
        key = cond.key.lower()

        # Multi-Factor Authentication
        if "multifactorauthpresent" in key:
            expected = any(v.lower() == "true" for v in cond.values)
            return self.var_mfa_present if expected else z3.Not(self.var_mfa_present)

        # Source IP restriction
        if "sourceip" in key:
            ip_matches = [self._match_pattern(self.var_source_ip, ip) for ip in cond.values]
            return z3.Or(ip_matches)

        # String matching condition
        if "stringequals" in op:
            matches = [self._match_pattern(self.var_principal, val) for val in cond.values]
            return z3.Or(matches)

        return None
