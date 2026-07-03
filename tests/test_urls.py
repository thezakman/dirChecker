from dirchecker import urls


def test_normalize_url_adds_scheme():
    assert urls.normalize_url("example.com/a") == "http://example.com/a"
    assert urls.normalize_url("https://x.com") == "https://x.com"
    assert urls.normalize_url("  example.com  ") == "http://example.com"


def test_url_depth():
    assert urls.url_depth("http://x.com/") == 0
    assert urls.url_depth("http://x.com/a/b/c") == 3


def test_is_binary_file():
    assert urls.is_binary_file("http://x.com/a/file.png")
    assert not urls.is_binary_file("http://x.com/a/dir/")


def test_has_file_extension():
    assert urls.has_file_extension("http://x.com/a/b.txt")
    assert not urls.has_file_extension("http://x.com/a/b/")


def test_has_double_slash():
    assert urls.has_double_slash("http://x.com/a//b")
    assert not urls.has_double_slash("http://x.com/a/b")


def test_expand_urls_generates_parents_and_is_deduped():
    out = urls.expand_urls(["http://x.com/a/b/c.txt"])
    assert "http://x.com/" in out
    assert "http://x.com/a/" in out
    assert "http://x.com/a/b/" in out
    # No duplicates and deepest-first ordering.
    assert len(out) == len(set(out))
    assert urls.url_depth(out[0]) >= urls.url_depth(out[-1])


def test_expand_urls_double_slash_variants():
    out = urls.expand_urls(["http://x.com/a/"], double_slash=True)
    assert any(urls.has_double_slash(u) for u in out)


def test_expand_urls_bypass_variants():
    out = urls.expand_urls(["http://x.com/a/"], bypass=True)
    assert "http://x.com/a/." in out
    assert "http://x.com/a/%2e/" in out
    assert "http://x.com/a;/" in out
    assert len(out) == len(set(out))


def test_bypass_variants_skip_files():
    assert urls._bypass_variants("http://x.com/a/file.txt") == []
