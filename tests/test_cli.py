import io

import pytest

from dirchecker import cli


def test_parse_headers():
    assert cli.parse_headers("A:1, B: 2") == {"A": "1", "B": "2"}
    assert cli.parse_headers(None) == {}
    assert cli.parse_headers("bad") == {}


def test_load_urls_from_file(tmp_path):
    f = tmp_path / "urls.txt"
    f.write_text("http://a.com\n\nhttp://b.com\n")
    args = cli.build_parser().parse_args(["-l", str(f)])
    assert cli.load_urls(args) == ["http://a.com", "http://b.com"]


def test_no_url_errors():
    with pytest.raises(SystemExit):
        cli.main([])


def test_load_urls_from_stdin(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO("http://a.com\n\nhttp://b.com\n"))
    args = cli.build_parser().parse_args(["-"])
    assert cli.load_urls(args) == ["http://a.com", "http://b.com"]


def test_new_flags_parse():
    args = cli.build_parser().parse_args(
        ["http://x.com/", "-bp", "-x", "http://127.0.0.1:8080", "-d", "0.5",
         "--no-head", "--same-host", "-f", "json"]
    )
    assert args.bypass is True
    assert args.proxy == "http://127.0.0.1:8080"
    assert args.delay == 0.5
    assert args.no_head is True
    assert args.same_host is True
    assert args.format == "json"


def test_output_requires_structured_format():
    with pytest.raises(SystemExit):
        cli.main(["http://x.com/", "-o", "out.json"])
