import requests

from dirchecker import detector


def _response(body: str, status: int = 200, headers: dict | None = None,
              url: str = "http://example.com/") -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp.url = url
    resp.headers["Content-Type"] = (headers or {}).get("Content-Type", "text/html")
    for key, value in (headers or {}).items():
        resp.headers[key] = value
    resp._content = body.encode("utf-8")
    return resp


def test_obvious_apache_listing():
    body = "<html><title>Index of /files</title><a href='..'>Parent Directory</a></html>"
    assert detector.is_directory_listing(_response(body))


def test_plain_page_is_not_listing():
    body = "<html><body><h1>Welcome</h1><p>Nothing here.</p></body></html>"
    assert not detector.is_directory_listing(_response(body))


def test_binary_content_type_skipped():
    body = "Index of / parent directory"
    resp = _response(body, headers={"Content-Type": "image/png"})
    assert not detector.is_directory_listing(resp)


def test_s3_bucket_listing():
    body = "<ListBucketResult><Contents><Key>a.txt</Key></Contents></ListBucketResult>"
    resp = _response(body, url="http://bucket.s3.amazonaws.com/",
                     headers={"Content-Type": "application/xml"})
    assert detector.is_directory_listing(resp)


def test_json_listing():
    body = '{"objects": ["a", "b"]}'
    resp = _response(body, headers={"Content-Type": "application/json"})
    assert detector.is_directory_listing(resp)


def test_score_threshold_many_links_and_table():
    links = "".join(f"<a href='f{i}'>f{i}</a>" for i in range(12))
    body = f"<table>{links}<td>x</td></table>"
    assert detector.is_directory_listing(_response(body))
