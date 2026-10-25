from dataclasses import asdict
from typing import Any, Dict, List

from .agent_event import AgentEvent
from .decision import Decision
from .mock_tools import MockTools
from .sentinel_agent import SentinelAgent


class EnforcementGateway:
    def __init__(self, sentinel: SentinelAgent, mock_tools: MockTools):
        self.sentinel = sentinel
        self.tools = mock_tools
        self.defense_enabled = True
        self.agent_tokens = {
            "TriageAgent": "tok-triage-8812",
            "SummarizerAgent": "tok-sum-4410",
            "PlannerAgent": "tok-plan-9931",
            "ExecutorAgent": "tok-exec-1102",
            "triage": "tok-triage-8812",
            "summarizer": "tok-sum-4410",
            "planner": "tok-plan-9931",
            "executor": "tok-exec-1102",
        }
        self.quarantined_agents = set()
        self.event_log: List[Dict[str, Any]] = []
        self.verdict_log: List[Dict[str, Any]] = []
        self.agent_taint_registry: Dict[str, List[str]] = {k: [] for k in self.agent_tokens}

    def set_defense_mode(self, enabled: bool):
        self.defense_enabled = enabled

    def reset_state(self):
        self.quarantined_agents.clear()
        self.event_log.clear()
        self.verdict_log.clear()
        for k in self.agent_taint_registry:
            self.agent_taint_registry[k] = []
        self.tools.reset()

    def validate_agent_token(self, agent_id: str, token: str) -> bool:
        return self.agent_tokens.get(agent_id) == token

    def tag_taint(self, agent_id: str, taint_label: str):
        labels = self.agent_taint_registry.setdefault(agent_id, [])
        if taint_label not in labels:
            labels.append(taint_label)

    def _log(self, event: AgentEvent, verdict, tool_output, defense: str):
        self.event_log.append(
            {
                "event": asdict(event),
                "verdict": asdict(verdict) if verdict else None,
                "tool_output": tool_output,
                "defense": defense,
            }
        )

    def process_event(self, event: AgentEvent, token: str) -> Dict[str, Any]:
        if not self.validate_agent_token(event.source_agent, token):
            return {"status": "REJECTED", "reason": "Invalid agent identity token."}

        if event.source_agent in self.quarantined_agents:
            event.execution_status = "BLOCKED"
            self._log(event, None, None, "ON" if self.defense_enabled else "OFF")
            return {
                "status": "BLOCKED",
                "reason": f"Agent '{event.source_agent}' is in QUARANTINE and revoked from protected tools.",
            }

        current_taints = sorted(set(event.provenance_labels + self.agent_taint_registry.get(event.source_agent, [])))
        event.provenance_labels = current_taints

        if event.target_agent in self.agent_taint_registry:
            for taint in current_taints:
                self.tag_taint(event.target_agent, taint)

        if not self.defense_enabled:
            event.execution_status = "EXECUTED"
            tool_output = None
            if event.requested_tool:
                tool_output = self._execute_tool_raw(event.requested_tool, event.requested_args or {})
            self._log(event, None, tool_output, "OFF")
            return {"status": "EXECUTED", "tool_output": tool_output, "verdict": None}

        verdict = self.sentinel.inspect_event(event)
        self.verdict_log.append(asdict(verdict))

        if verdict.decision == Decision.QUARANTINE:
            event.execution_status = "QUARANTINED"
            self.quarantined_agents.add(event.source_agent)
            if event.target_agent in self.agent_tokens:
                self.quarantined_agents.add(event.target_agent)
            self._log(event, verdict, None, "ON")
            return {"status": "QUARANTINED", "verdict": asdict(verdict), "reason": verdict.reason}

        if verdict.decision == Decision.BLOCK:
            event.execution_status = "BLOCKED"
            self._log(event, verdict, None, "ON")
            return {"status": "BLOCKED", "verdict": asdict(verdict), "reason": verdict.reason}

        if verdict.decision == Decision.ALLOW:
            event.execution_status = "EXECUTED"
            tool_output = None
            if event.requested_tool:
                tool_output = self._execute_tool_raw(event.requested_tool, event.requested_args or {})
            self._log(event, verdict, tool_output, "ON")
            return {"status": "EXECUTED", "verdict": asdict(verdict), "tool_output": tool_output}

        return {"status": "UNKNOWN"}

    def _execute_tool_raw(self, tool_name: str, args: Dict[str, Any]) -> str:
        if tool_name == "send_email":
            return self.tools.send_email(args.get("recipient", ""), args.get("subject", ""), args.get("body", ""))
        if tool_name == "write_file":
            return self.tools.write_file(args.get("filepath", ""), args.get("content", ""))
        if tool_name == "sync_calendar":
            return self.tools.sync_calendar(args.get("event_title", ""), args.get("time_slot", ""))
        if tool_name == "http_post":
            return self.tools.http_post(args.get("url", ""), args.get("data", ""))
        if tool_name == "update_agent_policy":
            return self.tools.update_agent_policy(args.get("agent", ""), args.get("role", ""))
        if tool_name == "internal_slack_notify":
            return self.tools.internal_slack_notify(args.get("channel", ""), args.get("message", ""))
        if tool_name == "update_crm_ticket":
            return self.tools.update_crm_ticket(args.get("ticket_id", ""), args.get("status", ""))
        if tool_name == "create_doc":
            return self.tools.create_doc(args.get("title", ""), args.get("content", ""))
        return f"Unknown tool '{tool_name}'"
