"""
benchmarks/policy_corpus.py
Standardized evaluation corpus of Multi-Cloud IAM Policies for SMT benchmarking.
Includes real-world AWS and Azure role patterns, vulnerable configurations, and least-privilege baselines.
"""

from typing import List, Dict, Any


BENCHMARK_POLICIES: List[Dict[str, Any]] = [
    {
        "name": "AdministratorAccess_Wildcard",
        "expected_admin": True,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]
        }
    },
    {
        "name": "ReadOnlyAccess_AllServices",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": ["*:Get*", "*:List*", "*:Describe*"], "Resource": "*"}]
        }
    },
    {
        "name": "S3_FullAccess_SingleBucket",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::analytics-data/*"}
            ]
        }
    },
    {
        "name": "Vulnerable_PrivilegeEscalation_PassRole",
        "expected_admin": True,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*"}
            ]
        }
    },
    {
        "name": "Hardened_PassRole_WithConditions",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::123456789012:role/ec2-app-worker",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
                }
            ]
        }
    },
    {
        "name": "ConfidentialS3_WithExplicitDeny",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::vault/*"},
                {
                    "Effect": "Deny",
                    "Action": "s3:*",
                    "Resource": "*",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "false"}}
                }
            ]
        }
    },
    {
        "name": "DeadCode_CompletelyShadowedStatement",
        "expected_admin": False,
        "has_redundancy": True,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Sid": "DenyAllDynamo", "Effect": "Deny", "Action": "dynamodb:*", "Resource": "*"},
                {"Sid": "UnreachableDynamoGet", "Effect": "Allow", "Action": "dynamodb:GetItem", "Resource": "arn:aws:dynamodb:*:*:table/Users"}
            ]
        }
    },
    {
        "name": "SecurityAudit_ReadCompliance",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["config:Get*", "cloudtrail:LookupEvents", "guardduty:List*"], "Resource": "*"}
            ]
        }
    },
    {
        "name": "DatabaseOperator_RDSLimited",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["rds:Describe*", "rds:StartDBInstance", "rds:StopDBInstance"], "Resource": "arn:aws:rds:us-east-1:123456789012:db:prod-*"}
            ]
        }
    },
    {
        "name": "KMS_Decrypt_KeyScoped",
        "expected_admin": False,
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "arn:aws:kms:us-east-1:123456789012:key/3b82f6e9-001"}
            ]
        }
    }
]
