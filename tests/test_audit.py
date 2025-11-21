"""Unit tests for the audit module."""

import pytest
from pathlib import Path
import tempfile
import json

from mobile_secrets_vault.audit import AuditLogger, Operation


class TestAuditLogger:
    """Test cases for audit logging."""

    def test_log_operation(self):
        """Test logging a basic operation."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.SET, key="TEST_KEY", success=True)

        logs = logger.get_logs()
        assert len(logs) == 1
        assert logs[0]["operation"] == "set"
        assert logs[0]["key"] == "TEST_KEY"
        assert logs[0]["success"] is True

    def test_log_with_metadata(self):
        """Test logging with additional metadata."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.ROTATE, success=True, secret_count=5, duration_ms=123)

        logs = logger.get_logs()
        assert logs[0]["metadata"]["secret_count"] == 5
        assert logs[0]["metadata"]["duration_ms"] == 123

    def test_log_error(self):
        """Test logging a failed operation."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.GET, key="MISSING_KEY", success=False, error="Key not found")

        logs = logger.get_logs()
        assert logs[0]["success"] is False
        assert logs[0]["error"] == "Key not found"

    def test_filter_by_key(self):
        """Test filtering logs by key."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.SET, key="KEY1", success=True)
        logger.log(Operation.SET, key="KEY2", success=True)
        logger.log(Operation.GET, key="KEY1", success=True)

        key1_logs = logger.get_logs(key="KEY1")
        assert len(key1_logs) == 2
        assert all(log["key"] == "KEY1" for log in key1_logs)

    def test_filter_by_operation(self):
        """Test filtering logs by operation type."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.SET, key="KEY1", success=True)
        logger.log(Operation.GET, key="KEY1", success=True)
        logger.log(Operation.DELETE, key="KEY1", success=True)
        logger.log(Operation.GET, key="KEY2", success=True)

        get_logs = logger.get_logs(operation=Operation.GET)
        assert len(get_logs) == 2
        assert all(log["operation"] == "get" for log in get_logs)

    def test_limit_logs(self):
        """Test limiting the number of returned logs."""
        logger = AuditLogger(in_memory=True)

        for i in range(10):
            logger.log(Operation.SET, key=f"KEY{i}", success=True)

        logs = logger.get_logs(limit=5)
        assert len(logs) == 5

    def test_logs_ordered_by_time(self):
        """Test that logs are returned in reverse chronological order."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.SET, key="FIRST", success=True)
        logger.log(Operation.SET, key="SECOND", success=True)
        logger.log(Operation.SET, key="THIRD", success=True)

        logs = logger.get_logs()

        # Most recent should be first
        assert logs[0]["key"] == "THIRD"
        assert logs[1]["key"] == "SECOND"
        assert logs[2]["key"] == "FIRST"

    def test_clear_logs(self):
        """Test clearing all logs."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.SET, key="KEY", success=True)
        assert len(logger.get_logs()) == 1

        logger.clear_logs()
        assert len(logger.get_logs()) == 0

    def test_persistent_logging(self):
        """Test logging to a file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "audit.log"
            logger = AuditLogger(log_file=log_file)

            logger.log(Operation.SET, key="PERSISTENT", success=True)
            logger.log(Operation.GET, key="PERSISTENT", success=True)

            # File should exist and contain logs
            assert log_file.exists()

            # Load a new logger from the same file
            logger2 = AuditLogger(log_file=log_file)
            logs = logger2.get_logs()

            # Should have loaded previous logs
            assert len(logs) >= 2

    def test_export_json(self):
        """Test exporting logs to JSON."""
        logger = AuditLogger(in_memory=True)

        logger.log(Operation.SET, key="KEY1", success=True)
        logger.log(Operation.GET, key="KEY1", success=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "export.json"
            logger.export_logs(output_path, format="json")

            assert output_path.exists()

            # Verify content
            with open(output_path) as f:
                data = json.load(f)

            assert len(data) == 2
            assert data[0]["operation"] == "set"

    def test_timestamp_format(self):
        """Test that timestamps are in ISO format."""
        logger = AuditLogger(in_memory=True)
        logger.log(Operation.INIT, success=True)

        logs = logger.get_logs()
        timestamp = logs[0]["timestamp"]

        # Should be ISO format ending with 'Z' (UTC)
        assert timestamp.endswith("Z")
        assert "T" in timestamp
