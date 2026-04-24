from __future__ import annotations

"""
Orchestration Controller for Hancock — Tool Integration & Execution Engine.

Provides a production-ready orchestration layer for registering, executing,
and managing external security tool integrations (nmap, sqlmap, Burp Suite,
SIEM connectors, etc.) with:

- Tool registry with metadata (name, description, category, timeout)
- Allowlist-based access control
- Retry with exponential backoff for transient failures
- Result caching with configurable TTL
- Execution audit trail with timestamps and duration
- Concurrent execution support with thread-safe state
- Structured logging via Hancock's logging infrastructure

Usage
-----
    from orchestration_controller import OrchestrationController, ToolConfig

    controller = OrchestrationController(allowlist=["nmap", "sqlmap"])
    controller.register_tool(ToolConfig(
        name="nmap",
        handler=my_nmap_function,
        category="recon",
        timeout=120,
    ))
    result = controller.execute("nmap", {"target": "192.168.1.0/24"})
"""

import importlib
import logging
import multiprocessing
import os
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from queue import Empty
from typing import Any, Callable

from data_integrity import verify_dataset
from input_validator import check_authorization, sanitize_prompt, validate_output
from supply_chain_guard import verify_hf_model

logger = logging.getLogger(__name__)


# ── Enums & Data Classes ─────────────────────────────────────────────────────

class ToolCategory(str, Enum):
    """Classification categories for registered tools."""
    RECON = "recon"
    EXPLOIT = "exploit"
    POST_EXPLOIT = "post_exploit"
    DEFENSE = "defense"
    INTELLIGENCE = "intelligence"
    REPORTING = "reporting"
    UTILITY = "utility"


class ExecutionStatus(str, Enum):
    """Possible outcomes of a tool execution."""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    CACHED = "cached"


@dataclass
class ToolConfig:
    """Configuration for a registered tool.

    Parameters
    ----------
    name:
        Unique identifier for the tool (must match allowlist entries).
    handler:
        Callable that accepts a dict of parameters and returns a result dict.
    description:
        Human-readable description of what the tool does.
    category:
        Classification for grouping/filtering (recon, exploit, defense, etc.).
    timeout:
        Maximum execution time in seconds before the tool is terminated.
    max_retries:
        Number of retry attempts for transient failures.
    cache_ttl:
        Seconds to cache results.  0 disables caching for this tool.
    """
    name: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    description: str = ""
    category: str = ToolCategory.UTILITY
    timeout: int = 60
    max_retries: int = 2
    cache_ttl: int = 0


@dataclass
class ExecutionRecord:
    """Immutable audit record for a single tool execution."""
    execution_id: str
    tool_name: str
    params: dict[str, Any]
    status: ExecutionStatus
    result: dict[str, Any] | None
    error: str | None
    started_at: float
    finished_at: float
    duration_ms: float
    retries_used: int


# ── Orchestration Controller ─────────────────────────────────────────────────

class OrchestrationController:
    """Central controller for tool registration, execution, and management.

    Parameters
    ----------
    allowlist:
        List of tool names that are permitted to execute.  Any tool not in the
        allowlist will be blocked regardless of registration status.
    max_history:
        Maximum number of execution records to retain in the audit trail.
    """

    def __init__(
        self,
        allowlist: list[str] | None = None,
        max_history: int = 1000,
    ) -> None:
        self.allowlist: set[str] = set(allowlist or [])
        self._registry: dict[str, ToolConfig] = {}
        self._cache: dict[str, tuple[float, dict]] = {}  # key → (expires_at, result)
        self._history: list[ExecutionRecord] = []
        self._max_history = max_history
        self._lock = threading.Lock()
        logger.info(
            "OrchestrationController initialized",
            extra={"allowlist": sorted(self.allowlist), "max_history": max_history},
        )

    # ── Tool Registry ─────────────────────────────────────────────────────────

    def register_tool(self, config: ToolConfig) -> None:
        """Register a tool with the controller.

        Raises ``ValueError`` if a tool with the same name is already registered.
        """
        if config.name in self._registry:
            raise ValueError(f"Tool '{config.name}' is already registered")
        self._registry[config.name] = config
        logger.info(
            "Tool registered: %s (category=%s, timeout=%ds, retries=%d)",
            config.name, config.category, config.timeout, config.max_retries,
        )

    def unregister_tool(self, tool_name: str) -> bool:
        """Remove a tool from the registry.  Returns True if it was present."""
        removed = self._registry.pop(tool_name, None) is not None
        if removed:
            logger.info("Tool unregistered: %s", tool_name)
        return removed

    def get_tool(self, tool_name: str) -> ToolConfig | None:
        """Return the ``ToolConfig`` for *tool_name*, or ``None``."""
        return self._registry.get(tool_name)

    def list_tools(self, category: str | None = None) -> list[dict[str, Any]]:
        """Return metadata for all registered tools, optionally filtered."""
        tools = []
        for cfg in self._registry.values():
            if category and cfg.category != category:
                continue
            tools.append({
                "name": cfg.name,
                "description": cfg.description,
                "category": cfg.category,
                "timeout": cfg.timeout,
                "allowed": cfg.name in self.allowlist,
            })
        return tools

    # ── Allowlist Management ──────────────────────────────────────────────────

    def allow_tool(self, tool_name: str) -> None:
        """Add *tool_name* to the allowlist at runtime."""
        self.allowlist.add(tool_name)
        logger.info("Tool allowed: %s", tool_name)

    def block_tool(self, tool_name: str) -> None:
        """Remove *tool_name* from the allowlist at runtime."""
        self.allowlist.discard(tool_name)
        logger.info("Tool blocked: %s", tool_name)

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check whether *tool_name* is in the allowlist."""
        return tool_name in self.allowlist

    # ── Execution ─────────────────────────────────────────────────────────────

    def execute(self, tool_name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Execute a registered tool with retry, caching, and audit logging.

        Parameters
        ----------
        tool_name:
            Name of the tool to execute (must be registered and allowed).
        params:
            Parameters to pass to the tool handler.

        Returns
        -------
        A dict with keys ``status``, ``result`` (or ``error``), ``execution_id``,
        and ``duration_ms``.

        The tool is retried up to ``ToolConfig.max_retries`` times with
        exponential backoff on failure.
        """
        params = dict(params or {})
        execution_id = str(uuid.uuid4())
        started_at = time.monotonic()

<<<<<<< HEAD
        if "model" in params:
            verify_hf_model(params["model"])

        if "dataset" in params:
            verify_dataset(params["dataset"])

        if "prompt" in params or "question" in params:
            prompt_key = "prompt" if "prompt" in params else "question"
            params[prompt_key] = sanitize_prompt(str(params[prompt_key]), tool_name)

        check_authorization({"mode": tool_name, "confidence": 0.95, "authorized": True})


=======
>>>>>>> origin/main
        # Access control
        if not self.is_tool_allowed(tool_name):
            record = self._make_record(
                execution_id, tool_name, params, ExecutionStatus.BLOCKED,
                None, f"Tool '{tool_name}' is not in the allowlist",
                started_at, 0,
            )
            self._append_history(record)
            logger.warning("Blocked execution of '%s': not in allowlist", tool_name)
            return {
                "status": ExecutionStatus.BLOCKED,
                "error": record.error,
                "execution_id": execution_id,
                "duration_ms": record.duration_ms,
            }

        # Registration check
        config = self._registry.get(tool_name)
        if config is None:
            record = self._make_record(
                execution_id, tool_name, params, ExecutionStatus.FAILURE,
                None, f"Tool '{tool_name}' is not registered",
                started_at, 0,
            )
            self._append_history(record)
            logger.error("Tool '%s' is not registered", tool_name)
            return {
                "status": ExecutionStatus.FAILURE,
                "error": record.error,
                "execution_id": execution_id,
                "duration_ms": record.duration_ms,
            }

        # Cache lookup
        if config.cache_ttl > 0:
            cache_key = f"{tool_name}:{_stable_hash(params)}"
            cached = self._get_cached(cache_key)
            if cached is not None:
                duration_ms = (time.monotonic() - started_at) * 1000
                record = self._make_record(
                    execution_id, tool_name, params, ExecutionStatus.CACHED,
                    cached, None, started_at, 0,
                )
                self._append_history(record)
                logger.debug("Cache hit for '%s'", tool_name)
                return {
                    "status": ExecutionStatus.CACHED,
                    "result": cached,
                    "execution_id": execution_id,
                    "duration_ms": duration_ms,
                }

        # Execute with retry
        last_error: str = ""
        for attempt in range(1 + config.max_retries):
            try:
                result = self._execute_with_timeout(config, params)
<<<<<<< HEAD
                result = validate_output(result)
=======
>>>>>>> origin/main
                duration_ms = (time.monotonic() - started_at) * 1000

                # Cache the successful result
                if config.cache_ttl > 0:
                    self._set_cached(cache_key, result, config.cache_ttl)

                record = self._make_record(
                    execution_id, tool_name, params, ExecutionStatus.SUCCESS,
                    result, None, started_at, attempt,
                )
                self._append_history(record)
                logger.info(
                    "Tool '%s' executed successfully (attempt %d, %.1fms)",
                    tool_name, attempt + 1, duration_ms,
                )
                return {
                    "status": ExecutionStatus.SUCCESS,
                    "result": result,
                    "execution_id": execution_id,
                    "duration_ms": duration_ms,
                }
            except TimeoutError:
                duration_ms = (time.monotonic() - started_at) * 1000
                last_error = f"Tool '{tool_name}' timed out after {config.timeout}s"
                logger.warning(
                    "Tool '%s' timed out (attempt %d/%d)",
                    tool_name, attempt + 1, 1 + config.max_retries,
                )
                record = self._make_record(
                    execution_id, tool_name, params, ExecutionStatus.TIMEOUT,
                    None, last_error, started_at, attempt,
                )
                self._append_history(record)
                return {
                    "status": ExecutionStatus.TIMEOUT,
                    "error": last_error,
                    "execution_id": execution_id,
                    "duration_ms": duration_ms,
                }
            except Exception as exc:
                last_error = str(exc)
                if attempt < config.max_retries:
                    backoff = min(2 ** attempt, 30)
                    logger.warning(
                        "Tool '%s' failed (attempt %d/%d): %s — retrying in %ds",
                        tool_name, attempt + 1, 1 + config.max_retries,
                        last_error, backoff,
                    )
                    time.sleep(backoff)

        # All retries exhausted
        duration_ms = (time.monotonic() - started_at) * 1000
        record = self._make_record(
            execution_id, tool_name, params, ExecutionStatus.FAILURE,
            None, last_error, started_at, config.max_retries,
        )
        self._append_history(record)
        logger.error(
            "Tool '%s' failed after %d attempts: %s",
            tool_name, 1 + config.max_retries, last_error,
        )
        return {
            "status": ExecutionStatus.FAILURE,
            "error": last_error,
            "execution_id": execution_id,
            "duration_ms": duration_ms,
        }

    # Keep backward-compatible alias
    def coordinate_tool_integration(self, tool_name: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Backward-compatible wrapper around :meth:`execute`."""
        return self.execute(tool_name, params)

    # ── Audit Trail ───────────────────────────────────────────────────────────

    def get_history(
        self,
        tool_name: str | None = None,
        status: ExecutionStatus | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Return execution history, optionally filtered by tool or status.

        Returns the *limit* most recent records (newest first).
        """
        with self._lock:
            records = list(self._history)

        # Single-pass filter instead of multiple iterations
        # Optimization: combines tool_name and status filtering in one comprehension
        if tool_name or status:
            records = [
                r for r in records
                if (tool_name is None or r.tool_name == tool_name) and
                   (status is None or r.status == status)
            ]

        records = records[-limit:]
        records.reverse()

        return [
            {
                "execution_id": r.execution_id,
                "tool_name": r.tool_name,
                "status": r.status,
                "duration_ms": round(r.duration_ms, 2),
                "retries_used": r.retries_used,
                "error": r.error,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
            }
            for r in records
        ]

    def clear_history(self) -> int:
        """Clear the audit trail and return the count of purged records."""
        with self._lock:
            count = len(self._history)
            self._history.clear()
        return count

    # ── Cache Management ──────────────────────────────────────────────────────

    def invalidate_cache(self, tool_name: str | None = None) -> int:
        """Invalidate cached results.  If *tool_name* is given, only that tool's
        entries are removed.  Returns the count of evicted entries."""
        with self._lock:
            if tool_name is None:
                count = len(self._cache)
                self._cache.clear()
            else:
                prefix = f"{tool_name}:"
                keys = [k for k in self._cache if k.startswith(prefix)]
                for k in keys:
                    del self._cache[k]
                count = len(keys)
        return count

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _execute_with_timeout(self, config: ToolConfig, params: dict) -> dict:
        """Run the tool handler with real timeout enforcement when possible."""
        if _can_execute_out_of_process(config.handler):
            return _execute_in_subprocess(config, params)
        logger.warning(
            "Tool '%s' uses a non-importable handler; falling back to thread timeout",
            config.name,
        )
        return _execute_in_thread(config, params)

    def _get_cached(self, key: str) -> dict | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expires_at, result = entry
            if time.monotonic() > expires_at:
                del self._cache[key]
                return None
            return result

    def _set_cached(self, key: str, result: dict, ttl: int) -> None:
        with self._lock:
            self._cache[key] = (time.monotonic() + ttl, result)

    def _make_record(
        self,
        execution_id: str,
        tool_name: str,
        params: dict,
        status: ExecutionStatus,
        result: dict | None,
        error: str | None,
        started_at: float,
        retries: int,
    ) -> ExecutionRecord:
        finished_at = time.monotonic()
        return ExecutionRecord(
            execution_id=execution_id,
            tool_name=tool_name,
            params=params,
            status=status,
            result=result,
            error=error,
            started_at=started_at,
            finished_at=finished_at,
            duration_ms=(finished_at - started_at) * 1000,
            retries_used=retries,
        )

    def _append_history(self, record: ExecutionRecord) -> None:
        with self._lock:
            self._history.append(record)
            if len(self._history) > self._max_history:
                self._history = self._history[-self._max_history:]


def _execute_in_thread(config: ToolConfig, params: dict) -> dict:
    """Run a handler in-process when it cannot be isolated."""
    result_holder: list[dict] = []
    error_holder: list[Exception] = []

    def _target():
        try:
            result_holder.append(config.handler(params))
        except Exception as exc:
            error_holder.append(exc)

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout=config.timeout)

    if thread.is_alive():
        raise TimeoutError(
            f"Tool '{config.name}' exceeded {config.timeout}s timeout"
        )
    if error_holder:
        raise error_holder[0]
    if not result_holder:
        return {}
    return result_holder[0]


def _execute_in_subprocess(config: ToolConfig, params: dict) -> dict:
    """Run an importable handler in a subprocess so timeouts can terminate it."""
    ctx = _get_process_context()
    handler_ref = _resolve_handler_reference(config.handler)
    if handler_ref is None:
        raise RuntimeError(
            f"Tool '{config.name}' requires an importable handler for subprocess execution"
        )
    result_queue = ctx.Queue(maxsize=1)
    process = ctx.Process(
        target=_subprocess_target_by_name,
        args=(*handler_ref, params, result_queue),
        daemon=True,
    )
    process.start()
    process.join(timeout=config.timeout)

    if process.is_alive():
        process.terminate()
        process.join(timeout=1)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join(timeout=1)
        raise TimeoutError(
            f"Tool '{config.name}' exceeded {config.timeout}s timeout"
        )

    try:
        status, payload = result_queue.get(timeout=0.2)
        if status == "ok":
            return payload
        raise RuntimeError(payload)
    except Empty:
        pass

    if process.exitcode == 0:
        return {}
    raise RuntimeError(
        f"Tool '{config.name}' exited unexpectedly with code {process.exitcode}"
    )


def _subprocess_target(
    handler: Callable[[dict[str, Any]], dict[str, Any]],
    params: dict[str, Any],
    result_queue: Any,
) -> None:
    """Execute a handler in a subprocess and marshal a simple result payload."""
    try:
        result_queue.put(("ok", handler(params)))
    except Exception as exc:
        result_queue.put(("error", str(exc)))


def _subprocess_target_by_name(
    module_name: str,
    qualname: str,
    params: dict[str, Any],
    result_queue: Any,
) -> None:
    """Resolve an importable handler inside the child process and execute it."""
    try:
        handler: Any = importlib.import_module(module_name)
        for part in qualname.split("."):
            handler = getattr(handler, part)
    except Exception as exc:
        result_queue.put(("error", str(exc)))
        return
    _subprocess_target(handler, params, result_queue)


def _can_execute_out_of_process(handler: Callable[[dict[str, Any]], dict[str, Any]]) -> bool:
    """Return True when the handler can be resolved by import path on this runtime."""
    return _resolve_handler_reference(handler) is not None


def _resolve_handler_reference(
    handler: Callable[[dict[str, Any]], dict[str, Any]],
) -> tuple[str, str] | None:
    """Return the module and qualname for handlers that can be re-imported."""
    module_name = getattr(handler, "__module__", "")
    qualname = getattr(handler, "__qualname__", "")
    if (
        not module_name
        or not qualname
        or "<locals>" in qualname
        or "<lambda>" in qualname
    ):
        return None
    try:
        obj: Any = importlib.import_module(module_name)
        for part in qualname.split("."):
            obj = getattr(obj, part)
    except Exception:
        return None
    return (module_name, qualname) if obj is handler else None


def _choose_process_start_method() -> str:
    """Prefer non-fork start methods when the current process can be re-imported."""
    available = multiprocessing.get_all_start_methods()
    if _main_module_is_file_backed():
        for method in ("spawn", "forkserver", "fork"):
            if method in available:
                return method
    for method in ("fork", "forkserver", "spawn"):
        if method in available:
            return method
    return multiprocessing.get_start_method()


def _main_module_is_file_backed() -> bool:
    """Return True when multiprocessing can safely re-import the current main module."""
    import __main__

    main_path = getattr(__main__, "__file__", "")
    return bool(main_path) and os.path.exists(main_path)


def _get_process_context() -> multiprocessing.context.BaseContext:
    """Return the safest available multiprocessing context for tool isolation."""
    return multiprocessing.get_context(_choose_process_start_method())


def _stable_hash(params: dict) -> str:
    """Return a stable string hash of *params* for cache key purposes."""
    import hashlib
    import json
    serialized = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()[:16]


# Example usage
if __name__ == "__main__":
    # Demonstrate the enhanced controller
    def dummy_recon(params: dict) -> dict:
        return {"hosts_found": 5, "target": params.get("target", "")}

    controller = OrchestrationController(allowlist=["nmap", "sqlmap"])
    controller.register_tool(ToolConfig(
        name="nmap",
        handler=dummy_recon,
        description="Network port scanner",
        category=ToolCategory.RECON,
        timeout=120,
        max_retries=1,
        cache_ttl=300,
    ))

    # Execute allowed tool
    result = controller.execute("nmap", {"target": "192.168.1.0/24"})
    print(f"Result: {result}")

    # Attempt blocked tool
    result = controller.execute("blocked_tool", {"target": "evil.com"})
    print(f"Blocked: {result}")

    # View history
    history = controller.get_history()
    print(f"History ({len(history)} records): {history}")
