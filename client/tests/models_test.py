"""Tests for Gafaelfawr client models."""

from __future__ import annotations

from rubin.gafaelfawr import (
    GafaelfawrGroup,
    GafaelfawrNotebookQuota,
    GafaelfawrTapQuota,
    GafaelfawrUserInfo,
)


def test_memory_bytes() -> None:
    quota = GafaelfawrNotebookQuota(cpu=1.0, memory=2.0)
    assert quota.memory_bytes == 2147483648


def test_supplemental_groups() -> None:
    userinfo = GafaelfawrUserInfo(
        username="someone",
        gid=4000,
        groups=[
            GafaelfawrGroup(name="a", id=1000),
            GafaelfawrGroup(name="b", id=1001),
            GafaelfawrGroup(name="c", id=1002),
        ],
    )
    assert userinfo.supplemental_groups == [1000, 1001, 1002]


def test_to_logging_context() -> None:
    notebook = GafaelfawrNotebookQuota(cpu=1.0, memory=4.0)
    assert notebook.to_logging_context() == {"cpu": 1.0, "memory": "4.0 GiB"}
    notebook = GafaelfawrNotebookQuota(cpu=1.5, memory=6.5, spawn=False)
    assert notebook.to_logging_context() == {
        "cpu": 1.5,
        "memory": "6.5 GiB",
        "spawn": False,
    }

    tap = GafaelfawrTapQuota(concurrent=4)
    assert tap.to_logging_context() == {"concurrent": 4}
