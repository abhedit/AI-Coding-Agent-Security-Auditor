"""Commercial plans. Edit prices/limits here; Stripe price IDs come from env."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_month: int | None    # USD; None = contact sales
    scans_per_month: int
    projects: int
    members: int
    history_days: int
    api_access: bool
    git_scans: bool
    sarif: bool
    badges: bool
    features: tuple[str, ...]


PLANS: dict[str, Plan] = {
    "free": Plan("free", "Starter", 0, 30, 2, 1, 14, True, True, False, False, (
        "30 scans / month", "2 projects", "All 45+ detection rules", "Web reports", "CLI & API access")),
    "pro": Plan("pro", "Pro", 29, 1000, 25, 3, 365, True, True, True, True, (
        "1,000 scans / month", "25 projects", "SARIF export for GitHub code scanning",
        "CI/CD GitHub Action", "Public security badges", "1-year history")),
    "team": Plan("team", "Team", 99, 10000, 250, 25, 730, True, True, True, True, (
        "10,000 scans / month", "250 projects", "25 team members", "Org-wide posture dashboard",
        "Priority support", "2-year history")),
    "enterprise": Plan("enterprise", "Enterprise", None, 10**9, 10**6, 10**6, 3650, True, True, True, True, (
        "Unlimited scans", "Self-hosted / VPC deployment", "SSO & audit logs", "Custom rules & policies",
        "Security review workshops with Abhijit", "SLA")),
}


def get_plan(pid: str) -> Plan:
    return PLANS.get(pid, PLANS["free"])
