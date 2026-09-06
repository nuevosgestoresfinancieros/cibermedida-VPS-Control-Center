"""Agent Manager contracts that only plan work and never activate adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from .audit import MetadataAuditLog
from .auth import AuthService, Permission


class AgentState(str, Enum):
    DEFINED = "defined"
    PLANNED = "planned"
    BLOCKED_BY_DEFAULT = "blocked_by_default"


@dataclass(frozen=True)
class AgentDescriptor:
    agent_id: str
    name: str
    responsibility: str
    capabilities: tuple[str, ...]
    state: AgentState


@dataclass(frozen=True)
class AgentTask:
    task_id: str
    agent_id: str
    requested_by: str
    task: str
    state: AgentState
    execution: str
    created_at: str


DEFAULT_AGENTS = (
    AgentDescriptor(
        agent_id="supervisor",
        name="Supervisor IA",
        responsibility="interpreta solicitudes y coordina planes",
        capabilities=("classify", "explain", "route"),
        state=AgentState.DEFINED,
    ),
    AgentDescriptor(
        agent_id="planner",
        name="AI Planner",
        responsibility="convierte intención en pasos verificables",
        capabilities=("plan", "risk", "approval"),
        state=AgentState.DEFINED,
    ),
    AgentDescriptor(
        agent_id="validator",
        name="Validator",
        responsibility="evalúa checks aportados sin ejecutarlos",
        capabilities=("validate", "post_check", "report"),
        state=AgentState.DEFINED,
    ),
    AgentDescriptor(
        agent_id="deploy",
        name="Deploy Agent",
        responsibility="prepara preflight y no despliega",
        capabilities=("preflight", "backup_gate", "post_validation"),
        state=AgentState.BLOCKED_BY_DEFAULT,
    ),
    AgentDescriptor(
        agent_id="backup",
        name="Backup Agent",
        responsibility="mantiene el contrato de backup y restore test",
        capabilities=("catalog", "verify", "restore_test"),
        state=AgentState.BLOCKED_BY_DEFAULT,
    ),
)


class AgentManager:
    def __init__(self, *, auth: AuthService, audit: MetadataAuditLog) -> None:
        self.auth = auth
        self.audit = audit
        self._tasks: dict[str, AgentTask] = {}

    @property
    def agents(self) -> tuple[AgentDescriptor, ...]:
        return DEFAULT_AGENTS

    @property
    def tasks(self) -> tuple[AgentTask, ...]:
        return tuple(self._tasks.values())

    def plan(self, *, session_id: str, agent_id: str, task: str) -> AgentTask:
        user = self.auth.require(session_id, Permission.REQUEST_APPROVAL)
        descriptor = next((agent for agent in DEFAULT_AGENTS if agent.agent_id == agent_id), None)
        if descriptor is None:
            raise ValueError("agent does not exist")
        if not task.strip() or len(task) > 2000:
            raise ValueError("task is empty or too long")
        planned = AgentTask(
            task_id=f"agent-task-{uuid4()}",
            agent_id=agent_id,
            requested_by=user.username,
            task=task.strip(),
            state=AgentState.PLANNED,
            execution="blocked_by_default",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._tasks[planned.task_id] = planned
        self.audit.append(
            user_id=user.user_id,
            actor=user.username,
            role=user.role.value,
            action="agent_task_planned",
            risk="MEDIUM",
            authorization="permission:REQUEST_APPROVAL",
            result=planned.execution,
            metadata={"agent_id": agent_id, "task_id": planned.task_id},
        )
        return planned
