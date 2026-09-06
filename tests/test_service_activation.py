from __future__ import annotations

import unittest

from control_center.audit import MetadataAuditLog
from control_center.auth import AuthService, Role
from control_center.deployments import DeploymentManager, DeploymentProviderEvidence, DeploymentState, DeploymentValidationEvidence
from control_center.rollbacks import RollbackManager, RollbackProviderEvidence, RollbackState
from control_center.service_activation import (
    DEFAULT_SERVICE_UNIT,
    FixedServiceActivation,
    ServiceActivationEvidence,
    ServiceActivationRequest,
    ServiceActivationState,
)


class FakeServiceRunner:
    def __init__(self) -> None:
        self.requests = []

    def run(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        self.requests.append(request)
        return ServiceActivationEvidence(
            provider="fixed-service-runner",
            unit=request.unit,
            operation=request.operation,
            state=ServiceActivationState.ACTIVATED,
            result="service_active_and_healthcheck_passed",
            verified=True,
        )


def request(**overrides: str) -> ServiceActivationRequest:
    values = {
        "unit": DEFAULT_SERVICE_UNIT,
        "project": "control-center",
        "operation": "deploy",
        "release": "commit-a",
        "requested_by": "admin",
        "approved_by": "javierofimatica2025",
        "approval_reference": "approval-1",
    }
    values.update(overrides)
    return ServiceActivationRequest(**values)


class FixedServiceActivationTests(unittest.TestCase):
    def test_status_is_bounded_and_blocked_without_runner(self) -> None:
        status = FixedServiceActivation().status()

        self.assertEqual(status["state"], "blocked_by_default")
        self.assertEqual(status["serviceUnit"], DEFAULT_SERVICE_UNIT)
        self.assertEqual(status["operations"], ["deploy", "rollback"])
        self.assertFalse(status["enabled"])
        self.assertFalse(status["runnerConfigured"])

    def test_disabled_by_default_and_does_not_call_runner(self) -> None:
        runner = FakeServiceRunner()
        provider = FixedServiceActivation(runner=runner)

        result = provider.activate(request=request())

        self.assertEqual(result.state, ServiceActivationState.BLOCKED_BY_DEFAULT)
        self.assertEqual(runner.requests, [])

    def test_preflight_is_metadata_only_and_reports_ready(self) -> None:
        runner = FakeServiceRunner()
        provider = FixedServiceActivation(enabled=True, runner=runner)

        result = provider.preflight(request=request())

        self.assertEqual(result.state, ServiceActivationState.READY)
        self.assertTrue(result.verified)
        self.assertEqual(runner.requests, [])

    def test_constructor_keeps_the_service_boundary_fixed(self) -> None:
        with self.assertRaises(ValueError):
            FixedServiceActivation(allowed_unit="apache2.service")
        with self.assertRaises(ValueError):
            FixedServiceActivation(allowed_project="other-project")

    def test_enabled_runner_receives_only_fixed_service_request(self) -> None:
        runner = FakeServiceRunner()
        provider = FixedServiceActivation(enabled=True, runner=runner)

        result = provider.activate(request=request(operation="rollback", release="commit-previous"))

        self.assertEqual(result.state, ServiceActivationState.ACTIVATED)
        self.assertTrue(result.verified)
        self.assertEqual(runner.requests[0].unit, DEFAULT_SERVICE_UNIT)
        self.assertEqual(runner.requests[0].operation, "rollback")

    def test_rejects_other_units_projects_and_operations(self) -> None:
        provider = FixedServiceActivation(enabled=True, runner=FakeServiceRunner())

        for invalid in (
            request(unit="apache2.service"),
            request(project="other-project"),
            request(operation="restart"),
            request(requested_by="javierofimatica2025"),
            request(approval_reference=""),
        ):
            with self.subTest(invalid=invalid):
                self.assertEqual(provider.activate(request=invalid).state, ServiceActivationState.REJECTED)

    def test_rejects_secret_like_metadata(self) -> None:
        provider = FixedServiceActivation(enabled=True, runner=FakeServiceRunner())

        result = provider.activate(request=request(release="token=do-not-store"))

        self.assertEqual(result.state, ServiceActivationState.REJECTED)

    def test_rejects_unsafe_runner_evidence(self) -> None:
        class UnsafeRunner:
            def run(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
                return ServiceActivationEvidence(
                    provider="fixed-service-runner",
                    unit=request.unit,
                    operation=request.operation,
                    state=ServiceActivationState.ACTIVATED,
                    result="stdout=raw-output",
                    verified=True,
                )

        provider = FixedServiceActivation(enabled=True, runner=UnsafeRunner())

        result = provider.activate(request=request())

        self.assertEqual(result.state, ServiceActivationState.FAILED)


class VerifiedBackupBoundary:
    provider_enabled = True
    provider = object()

    def is_verified(self, backup_id: str) -> bool:
        return backup_id == "backup-1"


class FakeReleaseProvider:
    name = "fixture-release-provider"
    def __init__(self) -> None:
        self.deploy_calls = 0
        self.rollback_calls = 0


    def deploy(self, *, plan):
        self.deploy_calls += 1
        return DeploymentProviderEvidence(
            provider=self.name,
            result="release_prepared",
            verified=True,
        )

    def validate(self, *, plan, deployment):
        return DeploymentValidationEvidence(
            validator=self.name,
            result="release_metadata_validated",
            verified=True,
        )

    def rollback(self, *, plan):
        self.rollback_calls += 1
        return RollbackProviderEvidence(
            provider=self.name,
            result="release_pointer_updated",
            verified=True,
        )


class UnsafeServiceActivation:
    name = "unsafe-service-activation"

    def preflight(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        return ServiceActivationEvidence(
            provider=self.name,
            unit=request.unit,
            operation=request.operation,
            state=ServiceActivationState.READY,
            result="activation_runner_ready",
            verified=True,
        )

    def activate(self, *, request: ServiceActivationRequest) -> ServiceActivationEvidence:
        return ServiceActivationEvidence(
            provider=self.name,
            unit=request.unit,
            operation=request.operation,
            state=ServiceActivationState.ACTIVATED,
            result="activation_reported_without_verification",
            verified=False,
        )

class ServiceActivationIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.auth = AuthService()
        self.auth.register_user(
            user_id="operator-id",
            username="operator",
            password="operator-password-123",
            role=Role.OPERATOR,
        )
        self.auth.register_user(
            user_id="approver-id",
            username="approver",
            password="approver-password-123",
            role=Role.ADMIN,
        )
        self.operator = self.auth.login(username="operator", password="operator-password-123")
        self.approver = self.auth.login(username="approver", password="approver-password-123")
        self.audit = MetadataAuditLog()
        self.release = FakeReleaseProvider()

    def test_deployment_stays_blocked_without_activation_runner(self) -> None:
        manager = DeploymentManager(
            auth=self.auth,
            audit=self.audit,
            backups=VerifiedBackupBoundary(),
            provider=self.release,
            provider_enabled=True,
            post_validator=self.release,
            service_activation=FixedServiceActivation(),
        )
        plan = manager.prepare(
            session_id=self.operator.session_id,
            project="control-center",
            commit="commit-a",
            checks={
                "git": True,
                "branch": True,
                "tests": True,
                "build": True,
                "dependencies": True,
                "disk": True,
                "backup": True,
                "backup_verification": True,
            },
            backup_id="backup-1",
        )
        manager.approve(session_id=self.approver.session_id, deployment_id=plan.deployment_id)

        result = manager.execute(session_id=self.operator.session_id, deployment_id=plan.deployment_id)

        self.assertEqual(result.state, DeploymentState.BLOCKED)
        self.assertIn("service activation: service activation is disabled", result.reason)
        self.assertEqual(self.release.deploy_calls, 0)

    def test_unverified_activation_cannot_verify_deployment(self) -> None:
        manager = DeploymentManager(
            auth=self.auth,
            audit=self.audit,
            backups=VerifiedBackupBoundary(),
            provider=self.release,
            provider_enabled=True,
            post_validator=self.release,
            service_activation=UnsafeServiceActivation(),
        )
        plan = manager.prepare(
            session_id=self.operator.session_id,
            project="control-center",
            commit="commit-a",
            checks={name: True for name in ("git", "branch", "tests", "build", "dependencies", "disk", "backup", "backup_verification")},
            backup_id="backup-1",
        )
        manager.approve(session_id=self.approver.session_id, deployment_id=plan.deployment_id)

        result = manager.execute(session_id=self.operator.session_id, deployment_id=plan.deployment_id)

        self.assertEqual(result.state, DeploymentState.FAILED)
        self.assertEqual(result.reason, "service activation evidence was not verified")

    def test_rollback_stays_blocked_without_activation_runner(self) -> None:
        manager = RollbackManager(
            auth=self.auth,
            audit=self.audit,
            provider=self.release,
            provider_enabled=True,
            service_activation=FixedServiceActivation(),
        )
        plan = manager.prepare(
            session_id=self.operator.session_id,
            project="control-center",
            rollback_type="release",
            target="commit-previous",
        )
        manager.approve(session_id=self.approver.session_id, rollback_id=plan.rollback_id)

        result = manager.execute(session_id=self.operator.session_id, rollback_id=plan.rollback_id)

        self.assertEqual(result.state, RollbackState.BLOCKED)
        self.assertIn("service activation: service activation is disabled", result.reason)
        self.assertEqual(self.release.rollback_calls, 0)


if __name__ == "__main__":
    unittest.main()
