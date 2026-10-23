import pytest

from dangl3.inputs import load_targets, normalize_hostname
from dangl3.models import ScanConfig


@pytest.mark.parametrize("raw, expected", [
    (" Blog.Example.COM. ", "blog.example.com"),
    ("a-b.example.com", "a-b.example.com"),
    ("bücher.example", "xn--bcher-kva.example"),
    ("a" * 63 + ".example.com", "a" * 63 + ".example.com"),
])
def test_normalize(raw, expected):
    assert normalize_hostname(raw) == expected


@pytest.mark.parametrize("raw", [
    "", "localhost", "https://blog.example.com", "blog.example.com/path",
    "blog.example.com/", "blog.example.com:443", "user@blog.example.com",
    "blog.example.com?x=1", "blog.example.com#fragment", "*.example.com",
    "a..example.com", "bad_name.example.com", "-bad.example.com", "bad-.example.com",
    "127.0.0.1", "[::1]", "blog.example.com..", "has space.example.com",
    "x" * 64 + ".example.com", ".example.com", "bad\\example.com",
    "x\x00.example.com", "blog.123", ("a" * 63 + ".") * 4 + "com",
])
def test_invalid_hostnames(raw):
    with pytest.raises(ValueError):
        normalize_hostname(raw)


def test_file_deduplicates_and_preserves_order(tmp_path):
    path = tmp_path / "targets.txt"
    path.write_text("\ufeff# test\nBlog.Example.com.\n\ndocs.example.com\nblog.example.com\n")
    assert load_targets(path) == ["blog.example.com", "docs.example.com"]


@pytest.mark.parametrize("content", ["", "# only comments\n\n", "ok.example.com\nhttps://bad.example.com\n"])
def test_invalid_file_content(tmp_path, content):
    path = tmp_path / "targets.txt"
    path.write_text(content)
    with pytest.raises(ValueError):
        load_targets(path)


def test_invalid_file_paths_and_encoding(tmp_path):
    for path in (tmp_path, tmp_path / "missing"):
        with pytest.raises(ValueError):
            load_targets(path)
    path = tmp_path / "binary"
    path.write_bytes(b"\xff\xfe")
    with pytest.raises(ValueError):
        load_targets(path)


@pytest.mark.parametrize("config", [
    {"timeout": 0}, {"timeout": -1}, {"timeout": float("nan")},
    {"timeout": float("inf")}, {"timeout": 121}, {"max_cname_depth": 0},
    {"max_redirects": -1}, {"max_body_bytes": 0},
])
def test_config_validation(config):
    with pytest.raises(ValueError):
        ScanConfig(**config)
