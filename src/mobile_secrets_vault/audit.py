"""
Audit logging functionality for Mobile Secrets Vault.

Tracks all operations performed on secrets with timestamps and metadata.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any
from enum import Enum


class Operation(Enum):
    """Enumeration of vault operations that can be audited."""

    GET = "get"
    SET = "set"
    DELETE = "delete"
    ROTATE = "rotate"
    INIT = "init"
    LIST_VERSIONS = "list_versions"


class AuditLogger:
    """
    Records and manages audit logs for vault operations.

    Audit logs track:
    - What operation was performed
    - Which secret key was accessed
    - When it happened
    - Whether it succeeded
    - Additional metadata
    """

    def __init__(self, log_file: Optional[Path] = None, in_memory: bool = False):
        """
        Initialize the audit logger.

        Args:
            log_file: Path to persistent log file (optional)
            in_memory: If True, keep logs in memory only
        """
        self.log_file = log_file
        self.in_memory = in_memory
        self._memory_logs: List[Dict[str, Any]] = []

        # Load existing logs if file exists
        if self.log_file and self.log_file.exists():
            self._load_logs()

    def log(
        self,
        operation: Operation,
        key: Optional[str] = None,
        success: bool = True,
        error: Optional[str] = None,
        **metadata: Any,
    ) -> None:
        """
        Record an audit log entry.

        Args:
            operation: The operation being performed
            key: The secret key being accessed (if applicable)
            success: Whether the operation succeeded
            error: Error message if operation failed
            **metadata: Additional metadata to include
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "operation": operation.value,
            "key": key,
            "success": success,
            "error": error,
            "metadata": metadata or {},
        }

        self._memory_logs.append(log_entry)

        # Persist to file if configured
        if self.log_file and not self.in_memory:
            self._append_to_file(log_entry)

    def get_logs(
        self,
        key: Optional[str] = None,
        operation: Optional[Operation] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs with optional filtering.

        Args:
            key: Filter by specific secret key
            operation: Filter by operation type
            limit: Maximum number of logs to return (most recent first)

        Returns:
            List of audit log entries
        """
        logs = self._memory_logs.copy()

        # Apply filters
        if key is not None:
            logs = [log for log in logs if log["key"] == key]

        if operation is not None:
            logs = [log for log in logs if log["operation"] == operation.value]

        # Sort by timestamp descending (most recent first)
        logs.sort(key=lambda x: x["timestamp"], reverse=True)

        # Apply limit
        if limit is not None:
            logs = logs[:limit]

        return logs

    def clear_logs(self) -> None:
        """Clear all audit logs (use with caution!)."""
        self._memory_logs.clear()
        if self.log_file and self.log_file.exists():
            self.log_file.unlink()

    def _load_logs(self) -> None:
        """Load existing logs from file."""
        try:
            with open(self.log_file, "r") as f:
                self._memory_logs = [json.loads(line) for line in f if line.strip()]
        except Exception as e:
            # If we can't load logs, start fresh
            self._memory_logs = []

    def _append_to_file(self, log_entry: Dict[str, Any]) -> None:
        """Append a single log entry to the file."""
        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception:
            # If we can't write to file, continue with in-memory only
            pass

    def export_logs(self, output_path: Path, format: str = "json") -> None:
        """
        Export audit logs to a file.

        Args:
            output_path: Where to save the exported logs
            format: Export format ('json' or 'csv')
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if format == "json":
            with open(output_path, "w") as f:
                json.dump(self._memory_logs, f, indent=2)
        elif format == "csv":
            import csv

            with open(output_path, "w", newline="") as f:
                if self._memory_logs:
                    fieldnames = ["timestamp", "operation", "key", "success", "error"]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for log in self._memory_logs:
                        row = {k: log.get(k) for k in fieldnames}
                        writer.writerow(row)
