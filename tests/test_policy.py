import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from secagent.config import Config
from secagent.policy import PolicyViolation, check_readable, check_tool, resolve_in_scope


@pytest.fixture
def workspace(tmp_path: Path):
    root = tmp_path / "app"
    (root / "pkg").mkdir(parents=True)
    (root / "pkg" / "views.py").write_text("x = 1\n")
    sibling = tmp_path / "app_old"          # shares a string prefix with the root
    sibling.mkdir()
    (sibling / "secret.py").write_text("KEY = 'x'\n")
    (tmp_path / "outside.txt").write_text("outside\n")
    return tmp_path, root


def cfg(root: Path, **kw) -> Config:
    return Config(authorized_roots=[root], **kw)


def test_relative_path_inside_root_is_allowed(workspace):
    _, root = workspace
    assert resolve_in_scope("pkg/views.py", cfg(root)) == (root / "pkg" / "views.py").resolve()


@pytest.mark.parametrize("bad", [
    "../outside.txt",
    "pkg/../../outside.txt",
    "../app_old/secret.py",        # prefix confusion: app vs app_old
])
def test_escaping_relative_paths_are_rejected(workspace, bad):
    _, root = workspace
    with pytest.raises(PolicyViolation):
        resolve_in_scope(bad, cfg(root))


def test_absolute_path_outside_root_is_rejected(workspace):
    tmp, root = workspace
    with pytest.raises(PolicyViolation):
        resolve_in_scope(str(tmp / "outside.txt"), cfg(root))


def test_absolute_path_inside_root_is_allowed(workspace):
    _, root = workspace
    p = str(root / "pkg" / "views.py")
    assert resolve_in_scope(p, cfg(root)).name == "views.py"


@pytest.mark.parametrize("bad", ["", "   ", "pkg/\x00views.py", "C:outside.txt"])
def test_malformed_paths_are_rejected(workspace, bad):
    _, root = workspace
    with pytest.raises(PolicyViolation):
        resolve_in_scope(bad, cfg(root))


def test_symlink_escaping_root_is_rejected(workspace):
    tmp, root = workspace
    link = root / "pkg" / "link.txt"
    try:
        os.symlink(tmp / "outside.txt", link)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs Developer Mode / admin on Windows")
    with pytest.raises(PolicyViolation):
        resolve_in_scope("pkg/link.txt", cfg(root))


def test_large_file_is_rejected(workspace):
    _, root = workspace
    big = root / "big.py"
    big.write_text("a" * 500)
    with pytest.raises(PolicyViolation):
        check_readable(big, cfg(root, max_file_bytes=100))


def test_directory_is_not_readable(workspace):
    _, root = workspace
    with pytest.raises(PolicyViolation):
        check_readable(root / "pkg", cfg(root))


def test_disabled_tool_is_rejected(workspace):
    _, root = workspace
    with pytest.raises(PolicyViolation):
        check_tool("run_lab_check", cfg(root))
    with pytest.raises(PolicyViolation):
        check_tool("shell", cfg(root))


def test_non_local_endpoint_is_rejected(workspace):
    _, root = workspace
    with pytest.raises(ValidationError):
        cfg(root, local_endpoint="http://api.example.com:11434")


def test_unknown_tool_in_config_is_rejected(workspace):
    _, root = workspace
    with pytest.raises(ValidationError):
        cfg(root, enabled_tools=["read_file", "shell"])


def test_lab_check_requires_manifest(workspace):
    _, root = workspace
    with pytest.raises(ValidationError):
        cfg(root, enabled_tools=["read_file", "run_lab_check"])
    with pytest.raises(ValidationError):
        cfg(root, runtime_tests_enabled=True)


def test_missing_root_is_rejected(tmp_path):
    with pytest.raises(ValidationError):
        Config(authorized_roots=[tmp_path / "does-not-exist"])
