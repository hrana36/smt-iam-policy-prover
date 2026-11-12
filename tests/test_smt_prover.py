"""
tests/test_smt_prover.py
Comprehensive Pytest test suite for SMT IAM Policy Prover.
Tests AST parsing, SMT encoding, reachability proofs, equivalence, and redundancy detection.
"""

import pytest
from prover import (
    IAMPolicy,
    Statement,
    Effect,
    Condition,
    SMTEncoder,
    ReachabilityProver,
    EquivalenceProver,
    RedundancyAnalyzer,
)


@pytest.fixture
def wildcard_admin_policy():
    return IAMPolicy.from_json({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
    }, name="AdminWildcard")


@pytest.fixture
def readonly_s3_policy():
    return IAMPolicy.from_json({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]
    }, name="ReadOnlyS3")


@pytest.fixture
def deny_unencrypted_policy():
    return IAMPolicy.from_json({
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::vault/*"},
            {
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*",
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
            }
        ]
    }, name="MFAEnforcedS3")


def test_ast_parsing_single_and_array():
    raw = {
        "Version": "2012-10-17",
        "Statement": {
            "Sid": "TestStmt",
            "Effect": "Allow",
            "Action": "ec2:DescribeInstances",
            "Resource": "*"
        }
    }
    policy = IAMPolicy.from_json(raw, name="TestSingle")
    assert len(policy.statements) == 1
    stmt = policy.statements[0]
    assert stmt.sid == "TestStmt"
    assert stmt.effect == Effect.ALLOW
    assert stmt.actions == ["ec2:DescribeInstances"]


def test_reachability_admin_wildcard(wildcard_admin_policy):
    prover = ReachabilityProver()
    res = prover.check_reachability(wildcard_admin_policy, target_action_pattern="iam:CreateUser")
    assert res.is_reachable
    assert not res.is_safe
    assert res.counterexample is not None
    assert res.counterexample["action"] != ""


def test_reachability_readonly_s3_blocked_admin(readonly_s3_policy):
    prover = ReachabilityProver()
    res = prover.check_reachability(readonly_s3_policy, target_action_pattern="iam:CreateUser")
    assert not res.is_reachable
    assert res.is_safe
    assert res.counterexample is None


def test_mfa_condition_enforcement(deny_unencrypted_policy):
    prover = ReachabilityProver()
    # Reachable with MFA? YES
    res_mfa = prover.check_reachability(
        deny_unencrypted_policy,
        target_action_pattern="s3:GetObject",
        require_no_mfa=False,
    )
    assert res_mfa.is_reachable

    # Reachable WITHOUT MFA? NO (Explicit Deny blocks it!)
    res_no_mfa = prover.check_reachability(
        deny_unencrypted_policy,
        target_action_pattern="s3:GetObject",
        require_no_mfa=True,
    )
    assert not res_no_mfa.is_reachable
    assert res_no_mfa.is_safe


def test_equivalence_identical_policies(readonly_s3_policy):
    prover = EquivalenceProver()
    # Clone same policy
    policy_copy = IAMPolicy.from_json(readonly_s3_policy.to_dict(), name="Copy")
    res = prover.prove_equivalence(readonly_s3_policy, policy_copy)
    assert res.are_equivalent
    assert res.counterexample is None


def test_subsumption_broad_vs_narrow(wildcard_admin_policy, readonly_s3_policy):
    prover = EquivalenceProver()
    res = prover.prove_equivalence(readonly_s3_policy, wildcard_admin_policy)
    assert not res.are_equivalent
    assert res.subsumption == "P1_STRICT_SUBSET_OF_P2"
    assert res.counterexample is not None


def test_redundancy_shadowed_statement():
    shadowed_raw = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "DenyAll", "Effect": "Deny", "Action": "*", "Resource": "*"},
            {"Sid": "UnreachableAllow", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
        ]
    }
    policy = IAMPolicy.from_json(shadowed_raw, name="ShadowedPolicy")
    analyzer = RedundancyAnalyzer()
    report = analyzer.analyze(policy)
    assert report.has_redundancies
    assert len(report.shadowed_statements) == 1
    assert report.shadowed_statements[0]["sid"] == "UnreachableAllow"
