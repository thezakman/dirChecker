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
