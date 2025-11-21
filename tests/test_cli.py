"""Integration tests for the CLI."""

import pytest
from click.testing import CliRunner
import tempfile
from pathlib import Path

from mobile_secrets_vault.cli import cli
from mobile_secrets_vault import CryptoEngine


class TestCLI:
    """Test cases for command-line interface."""

    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()

    @pytest.fixture
    def temp_dir(self):
        """Create temporary directory for tests."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_cli_version(self, runner):
        """Test --version flag."""
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_init_command(self, runner, temp_dir):
        """Test vault init command."""
        result = runner.invoke(cli, ["init", "--output-dir", str(temp_dir / ".vault")])

        assert result.exit_code == 0
        assert (temp_dir / ".vault" / "master.key").exists()
        assert (temp_dir / ".vault" / "secrets.yaml").exists()
        assert "✅" in result.output

    def test_init_existing_vault(self, runner, temp_dir):
        """Test init fails if vault already exists."""
        vault_dir = temp_dir / ".vault"
        vault_dir.mkdir()
        (vault_dir / "master.key").touch()

        result = runner.invoke(cli, ["init", "--output-dir", str(vault_dir)])

        assert result.exit_code == 1
        assert "already exists" in result.output

    def test_init_force_overwrite(self, runner, temp_dir):
        """Test init with --force overwrites existing vault."""
        vault_dir = temp_dir / ".vault"
        vault_dir.mkdir()
        (vault_dir / "master.key").write_bytes(b"old key")

        result = runner.invoke(cli, ["init", "--output-dir", str(vault_dir), "--force"])

        assert result.exit_code == 0
        # Key should be different
        assert (vault_dir / "master.key").read_bytes() != b"old key"

    def test_set_and_get_secret(self, runner, temp_dir):
        """Test setting and getting a secret via CLI."""
        # Initialize vault
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        # Set a secret
        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "set",
                "TEST_KEY",
                "test-value",
            ],
        )
        assert result.exit_code == 0
        assert "✅" in result.output

        # Get the secret
        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "get",
                "TEST_KEY",
            ],
        )
        assert result.exit_code == 0
        assert "test-value" in result.output

    def test_set_with_stdin(self, runner, temp_dir):
        """Test setting secret from stdin."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "set",
                "API_KEY",
                "--stdin",
            ],
            input="secret-from-stdin",
        )

        assert result.exit_code == 0

    def test_get_raw_output(self, runner, temp_dir):
        """Test getting secret with --raw flag."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "set",
                "RAW_KEY",
                "raw-value",
            ],
        )

        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "get",
                "RAW_KEY",
                "--raw",
            ],
        )

        assert result.output.strip() == "raw-value"

    def test_get_nonexistent_secret(self, runner, temp_dir):
        """Test getting a secret that doesn't exist."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "get",
                "NONEXISTENT",
            ],
        )

        assert result.exit_code == 1
        assert "not found" in result.output

    def test_delete_secret(self, runner, temp_dir):
        """Test deleting a secret."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        # Set a secret
        runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "set",
                "DELETEME",
                "value",
            ],
        )

        # Delete with --yes to skip confirmation
        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "delete",
                "DELETEME",
                "--yes",
            ],
        )

        assert result.exit_code == 0
        assert "✅" in result.output

    def test_list_versions(self, runner, temp_dir):
        """Test listing version history."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        # Create multiple versions
        for i in range(3):
            runner.invoke(
                cli,
                [
                    "--vault-file",
                    str(temp_dir / "secrets.yaml"),
                    "--master-key-file",
                    str(temp_dir / "master.key"),
                    "set",
                    "VERSIONED",
                    f"value-{i}",
                ],
            )

        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "list-versions",
                "VERSIONED",
            ],
        )

        assert result.exit_code == 0
        assert "Version 1" in result.output
        assert "Version 2" in result.output
        assert "Version 3" in result.output

    def test_list_keys(self, runner, temp_dir):
        """Test listing all keys."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        # Add multiple secrets
        for key in ["KEY1", "KEY2", "KEY3"]:
            runner.invoke(
                cli,
                [
                    "--vault-file",
                    str(temp_dir / "secrets.yaml"),
                    "--master-key-file",
                    str(temp_dir / "master.key"),
                    "set",
                    key,
                    "value",
                ],
            )

        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "list",
            ],
        )

        assert result.exit_code == 0
        assert "KEY1" in result.output
        assert "KEY2" in result.output
        assert "KEY3" in result.output

    def test_rotate_command(self, runner, temp_dir):
        """Test key rotation command."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        # Add a secret
        runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "set",
                "BEFORE_ROTATION",
                "value",
            ],
        )

        # Rotate with --yes to skip confirmation
        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "rotate",
                "--new-key-file",
                str(temp_dir / "new_master.key"),
                "--yes",
            ],
        )

        assert result.exit_code == 0
        assert "✅" in result.output
        assert (temp_dir / "new_master.key").exists()

    def test_audit_command(self, runner, temp_dir):
        """Test audit log command."""
        runner.invoke(cli, ["init", "--output-dir", str(temp_dir)])

        # Perform some operations
        runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "set",
                "AUDIT_KEY",
                "value",
            ],
        )

        runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "get",
                "AUDIT_KEY",
            ],
        )

        # Check audit log
        result = runner.invoke(
            cli,
            [
                "--vault-file",
                str(temp_dir / "secrets.yaml"),
                "--master-key-file",
                str(temp_dir / "master.key"),
                "audit",
            ],
        )

        assert result.exit_code == 0
        # Check that audit log is shown (init operation should always be there)
        assert "Audit log" in result.output
        assert "init" in result.output or "set" in result.output

    def test_without_master_key(self, runner, temp_dir):
        """Test that commands fail gracefully without master key."""
        result = runner.invoke(cli, ["get", "SOME_KEY"])

        assert result.exit_code == 1
        assert "Master key not found" in result.output or "init" in result.output
