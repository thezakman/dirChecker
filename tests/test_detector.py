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


def test_s3_compatible_listing_on_any_host():
    """A MinIO/DigitalOcean/Backblaze bucket uses the same XML on any domain."""
    body = (
        "<ListBucketResult><CommonPrefixes><Prefix>x/</Prefix></CommonPrefixes>"
        "</ListBucketResult>"
    )
    resp = _response(body, url="http://files.example.com/",
                     headers={"Content-Type": "application/xml"})
    assert detector.is_directory_listing(resp)


def test_azure_blob_listing():
    body = "<EnumerationResults><Blobs><Blob><Name>a</Name></Blob></Blobs></EnumerationResults>"
    resp = _response(body, url="http://acct.blob.core.windows.net/c/",
                     headers={"Content-Type": "application/xml"})
    assert detector.is_directory_listing(resp)


def test_json_listing():
    body = '{"objects": ["a", "b"]}'
    resp = _response(body, headers={"Content-Type": "application/json"})
    assert detector.is_directory_listing(resp)


def test_listing_pattern_with_links_and_table():
    """A real listing signal plus structural cues clears the threshold."""
    links = "".join(f"<a href='f{i}'>f{i}</a>" for i in range(12))
    body = f"<h1>Directory: /data</h1><table>{links}<td>Last Modified</a></td></table>"
    assert detector.is_directory_listing(_response(body))


def test_links_and_table_without_listing_signal_not_flagged():
    """Many links and a table alone (a normal page) must not be flagged."""
    links = "".join(f"<a href='f{i}'>f{i}</a>" for i in range(12))
    body = f"<table>{links}<td>x</td></table>"
    assert not detector.is_directory_listing(_response(body))


def test_403_error_page_not_flagged():
    """A 403 error page without listing content is not a vulnerability."""
    body = (
        "<html><head><title>403 Proibido</title></head>"
        "<body><h1>Acesso negado</h1><p>Voce nao tem permissao.</p></body></html>"
    )
    assert not detector.is_directory_listing(_response(body, status=403))


def test_403_does_not_flag_non_cloud_url():
    """Even a content-rich 403 page on a normal host is not a listing."""
    links = "".join(f"<a href='/menu/{i}'>item {i}</a>" for i in range(20))
    body = f"<html><body><nav>{links}</nav><h1>Forbidden by policy</h1></body></html>"
    resp = _response(body, status=403, url="https://www.example.coop.br/repositorio/")
    assert not detector.is_directory_listing(resp)
