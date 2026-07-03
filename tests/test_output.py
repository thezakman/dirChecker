import csv
import io
import json

import requests

from dirchecker import output
from dirchecker.models import CheckResult


def _result(url="http://x.com/", is_listing=False, status=200, note=None):
    resp = requests.Response()
    resp.status_code = status
    resp.url = url
    resp.headers["Content-Type"] = "text/html"
    resp.headers["Content-Length"] = "123"
    resp.headers["Server"] = "nginx"
    resp._content = b"body"
    return CheckResult(url=url, depth=0, is_listing=is_listing, response=resp, note=note)


def test_result_to_dict_fields():
    d = output.result_to_dict(_result(is_listing=True, note="hi"))
    assert d["url"] == "http://x.com/"
    assert d["status_code"] == 200
    assert d["is_listing"] is True
    assert d["server"] == "nginx"
    assert d["note"] == "hi"


def test_to_json_is_valid_and_filters_listings():
    results = [_result(url="http://a/", is_listing=True), _result(url="http://b/")]
    parsed = json.loads(output.to_json(results, only_listings=True))
    assert [r["url"] for r in parsed] == ["http://a/"]
    assert len(json.loads(output.to_json(results))) == 2


def test_to_jsonl_one_object_per_line():
    results = [_result(url="http://a/"), _result(url="http://b/")]
    lines = output.to_jsonl(results).splitlines()
    assert len(lines) == 2
    assert all(json.loads(line)["url"] for line in lines)


def test_to_csv_has_header_and_rows():
    rows = list(csv.DictReader(io.StringIO(output.to_csv([_result()]))))
    assert rows[0]["url"] == "http://x.com/"
    assert rows[0]["is_listing"] == "False"


def test_serialize_unknown_format_raises():
    try:
        output.serialize([], "xml")
    except ValueError:
        return
    raise AssertionError("expected ValueError")
