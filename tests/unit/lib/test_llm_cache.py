# Copyright (C) 2025-2026 JoeyZzZzZz
# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from treasure_map.lib.llm_cache.cache import LLMCache, _normalize_whitespace


def test_miss_then_hit(tmp_path):
    cache = LLMCache(tmp_path / "cache.db")
    result = cache.get("function_summary", "foo\n---CALLEES---\n[]", "summarize_v1")
    assert result is None

    cache.set(
        "function_summary",
        "foo\n---CALLEES---\n[]",
        "summarize_v1",
        "deepseek-chat",
        "S",
        {"content": "does stuff"},
        0.001,
    )
    result = cache.get("function_summary", "foo\n---CALLEES---\n[]", "summarize_v1")
    assert result is not None
    assert result["content"] == "does stuff"
    cache.close()


def test_hit_count_increments(tmp_path):
    cache = LLMCache(tmp_path / "cache.db")
    cache.set("function_summary", "x\n---CALLEES---\n[]", "v1", "m", "S", {"c": "y"}, 0.0)
    cache.get("function_summary", "x\n---CALLEES---\n[]", "v1")
    cache.get("function_summary", "x\n---CALLEES---\n[]", "v1")
    stats = cache.stats()
    assert stats["hits_total"] == 2
    cache.close()


def test_different_prompt_version_miss(tmp_path):
    cache = LLMCache(tmp_path / "cache.db")
    cache.set("function_summary", "x\n---CALLEES---\n[]", "v1", "m", "S", {"c": "old"}, 0.0)
    assert cache.get("function_summary", "x\n---CALLEES---\n[]", "v2") is None
    cache.close()


def test_whitespace_normalization(tmp_path):
    """Two inputs that differ only in leading/trailing whitespace per line
    and collapsed internal runs should hit the same cache entry."""
    cache = LLMCache(tmp_path / "cache.db")
    # input_a has extra leading spaces on each line (common in Ghidra output)
    input_a = "int  main() {\n  return  0;\n}\n---CALLEES---\n[]"
    # input_b is the same code with minimal whitespace
    input_b = "int main() {\n return 0;\n}\n---CALLEES---\n[]"
    cache.set("function_summary", input_a, "v1", "m", "S", {"c": "norm"}, 0.0)
    assert cache.get("function_summary", input_b, "v1") is not None
    cache.close()


def test_purge_by_prompt_version(tmp_path):
    cache = LLMCache(tmp_path / "cache.db")
    cache.set("function_summary", "a\n---CALLEES---\n[]", "v1", "m", "S", {"c": "a"}, 0.0)
    cache.set("function_summary", "b\n---CALLEES---\n[]", "v1", "m", "S", {"c": "b"}, 0.0)
    deleted = cache.purge_by_prompt_version("function_summary", "v1")
    assert deleted == 2
    assert cache.get("function_summary", "a\n---CALLEES---\n[]", "v1") is None
    cache.close()


def test_stats_by_task_and_model(tmp_path):
    cache = LLMCache(tmp_path / "cache.db")
    cache.set("function_summary", "x\n---CALLEES---\n[]", "v1", "deepseek-chat", "S", {}, 0.01)
    cache.set("library_summary", "lib\n---SUMMARIES---\n[]", "v1", "deepseek-r1", "M", {}, 0.05)
    cache.get("function_summary", "x\n---CALLEES---\n[]", "v1")
    stats = cache.stats()
    assert stats["total_entries"] == 2
    assert "function_summary" in stats["by_task"]
    assert "deepseek-chat" in stats["by_model"]
    cache.close()


def test_normalize_whitespace():
    assert _normalize_whitespace("a  b\t\tc") == "a b c"
    assert _normalize_whitespace("  x  \n  y  ") == "x\ny"
