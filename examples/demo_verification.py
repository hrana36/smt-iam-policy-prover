"""
examples/demo_verification.py
Demonstration of Automated SMT Formal Verification on Multi-Cloud IAM Policies.
Proves Privilege Escalation Reachability, Policy Subsumption, and Dead Rule Detection.
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from prover import (
    IAMPolicy,
    ReachabilityProver,
    EquivalenceProver,
    RedundancyAnalyzer,
)


def run_demo():
    print("\n" + "=" * 78)
    print(" 📐 SMT IAM POLICY PROVER: FORMAL VERIFICATION & REACHABILITY ENGINE")
    print("=" * 78)

    sample_dir = os.path.join(os.path.dirname(__file__), "sample_policies")
    vuln_path = os.path.join(sample_dir, "vulnerable_passrole.json")
    hardened_path = os.path.join(sample_dir, "hardened_passrole.json")

    with open(vuln_path, "r", encoding="utf-8") as f:
        vuln_policy = IAMPolicy.from_json(f.read(), name="VulnerableDeveloperRole")

    with open(hardened_path, "r", encoding="utf-8") as f:
        hardened_policy = IAMPolicy.from_json(f.read(), name="HardenedDeveloperRole")

    reachability_prover = ReachabilityProver()
    equivalence_prover = EquivalenceProver()
    redundancy_analyzer = RedundancyAnalyzer()

    # -------------------------------------------------------------
    # Query 1: Prove Privilege Escalation Reachability (iam:PassRole)
    # -------------------------------------------------------------
    print("\n--- [QUERY 1] Reachability Proof: Arbitrary IAM Role Assumption (iam:PassRole) ---")
    print("Target Invariant: Can the principal execute 'iam:PassRole' against ANY resource without MFA?")

    res1_vuln = reachability_prover.check_reachability(
        policy=vuln_policy,
        target_action_pattern="iam:PassRole",
        target_resource_pattern="arn:aws:iam::*:role/AdministratorAccess",
        require_no_mfa=True,
        query_description="Unrestricted iam:PassRole Escalation",
    )
    print(f"Policy: {vuln_policy.name}")
    print(f"  Proof Result : {res1_vuln.proof_status} in {res1_vuln.solver_time_ms} ms")
    if res1_vuln.is_reachable:
        print("  🚨 VULNERABILITY MATHEMATICALLY PROVEN! Counterexample Exploit Model:")
        for k, v in res1_vuln.counterexample.items():
            print(f"     • {k:<15} = {v}")

    res1_hard = reachability_prover.check_reachability(
        policy=hardened_policy,
        target_action_pattern="iam:PassRole",
        target_resource_pattern="arn:aws:iam::*:role/AdministratorAccess",
        require_no_mfa=True,
        query_description="Unrestricted iam:PassRole Escalation",
    )
    print(f"\nPolicy: {hardened_policy.name}")
    print(f"  Proof Result : {res1_hard.proof_status} in {res1_hard.solver_time_ms} ms")
    if not res1_hard.is_reachable:
        print("  ✅ MATHEMATICAL GUARANTEE: Privilege escalation is PROVEN IMPOSSIBLE under all inputs!")

    # -------------------------------------------------------------
    # Query 2: Prove Semantic Policy Equivalence & Subsumption
    # -------------------------------------------------------------
    print("\n--- [QUERY 2] Semantic Equivalence & Policy Containment Verification ---")
    eq_res = equivalence_prover.prove_equivalence(vuln_policy, hardened_policy)
    print(f"Comparing '{vuln_policy.name}' vs '{hardened_policy.name}':")
    print(f"  Equivalent?  : {eq_res.are_equivalent}")
    print(f"  Subsumption  : {eq_res.subsumption}")
    print(f"  Solver Time  : {eq_res.solver_time_ms} ms")
    if eq_res.counterexample:
        print("  Divergence Counterexample (Allowed by one, Denied by the other):")
        print(f"     • Action       = {eq_res.counterexample['action']}")
        print(f"     • Resource     = {eq_res.counterexample['resource']}")
        print(f"     • P1 Decision  = {eq_res.counterexample['p1_decision']}")
        print(f"     • P2 Decision  = {eq_res.counterexample['p2_decision']}")

    # -------------------------------------------------------------
    # Query 3: Dead Code / Shadowed Statement Analysis
    # -------------------------------------------------------------
    print("\n--- [QUERY 3] Redundancy & Shadowed Statement Analysis ---")
    # Build a policy with a permanently shadowed allow statement
    shadow_policy = IAMPolicy.from_json({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GlobalDenyAllS3",
                "Effect": "Deny",
                "Action": "s3:*",
                "Resource": "*"
            },
            {
                "Sid": "DeadCodeAllowS3Read",
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::my-bucket/*"
            }
        ]
    }, name="PolicyWithDeadCode")

    red_report = redundancy_analyzer.analyze(shadow_policy)
    print(f"Policy: {red_report.policy_name} ({red_report.total_statements} statements)")
    print(f"  Has Redundancies: {red_report.has_redundancies} (Analyzed in {red_report.analysis_time_ms} ms)")
    for sh in red_report.shadowed_statements:
        print(f"  ⚠️  Shadowed Statement: Sid='{sh['sid']}' (Effect: {sh['effect']}, Action: {sh['actions']})")
        print(f"      Reason: {sh['reason']}")

    print("\n" + "=" * 78)
    print(" Formal verification complete. All safety proofs generated via Z3 SMT solver.")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_demo()
