import httpx
import pytest

from permitprobe.policy import Redirect
from permitprobe.response_contracts import no_store_matches, private_cache_matches, redirect_matches


@pytest.mark.parametrize(
    "cache,vary,expected",
    [
        ("private, max-age=240", "Cookie", True),
        ("PRIVATE, max-age=0, must-revalidate", "Accept, cOoKiE", True),
        ("private", "*", True),
        ("no-store", "", True),
        ("no-store, private", "", True),
        ("", "Cookie", False),
        ("public, max-age=240", "Cookie", False),
        ("private, public", "Cookie", False),
        ("private, s-maxage=0", "Cookie", False),
        ('private="Set-Cookie"', "Cookie", False),
        ("no-store=1", "", False),
        ("no-store, must-understand", "", False),
        ("no-store, public", "", False),
        ("private, private", "Cookie", False),
        ("private, max-age=10, max-age=20", "Cookie", False),
        ("private", "", False),
        ("private", "Accept-Encoding", False),
        ("private", '"Cookie"', False),
        ("private", "*, Cookie", False),
        ("private, x-unknown=1", "Cookie", False),
    ],
)
def test_private_cache_contract(cache, vary, expected):
    headers = httpx.Headers({"Cache-Control": cache, "Vary": vary})
    assert private_cache_matches(headers, "Cookie") is expected


def test_bearer_cache_is_bound_to_authorization_header():
    headers = httpx.Headers({"Cache-Control": "private", "Vary": "Authorization"})
    assert private_cache_matches(headers, "Authorization")
    assert not private_cache_matches(headers, "Cookie")


@pytest.mark.parametrize(
    "cache,expected",
    [
        ("no-store", True),
        ("private, no-store, max-age=0", True),
        ("private", False),
        ("public, no-store", False),
        ("no-store=1", False),
        ("no-store, unknown", False),
    ],
)
def test_public_no_store_contract(cache, expected):
    assert no_store_matches(httpx.Headers({"Cache-Control": cache})) is expected


@pytest.mark.parametrize(
    "location,expected",
    [
        ("https://storage.example.invalid/files/alice/sample.pdf?token=fake", True),
        ("https://STORAGE.example.invalid:443/files/alice/sample.pdf?token=fake", True),
        ("https://storage.example.invalid/files/bob/sample.pdf?token=fake", False),
        ("https://other.example.invalid/files/alice/sample.pdf?token=fake", False),
        ("https://storage.example.invalid:444/files/alice/sample.pdf?token=fake", False),
        ("https://storage.example.invalid/login?token=fake", False),
        ("/files/alice/sample.pdf?token=fake", False),
        ("//storage.example.invalid/files/alice/sample.pdf?token=fake", False),
        ("https://user@storage.example.invalid/files/alice/sample.pdf?token=fake", False),
        ("https://@storage.example.invalid/files/alice/sample.pdf?token=fake", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=fake#fragment", False),
        ("https://storage.example.invalid/files/alice/sample.pdf", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=+", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=a&token=b", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=a&extra=b", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=a&invalid", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=%ZZ", False),
        ("https://storage.example.invalid/files/alice/sample.pdf?token=a%0Ab", False),
        ("https://storage.example.invalid/files/%61lice/sample.pdf?token=fake", False),
        ("https://storage.example.invalid/files/x/../alice/sample.pdf?token=fake", False),
        ("https://storage.example.invalid\\evil/files/alice/sample.pdf?token=fake", False),
    ],
)
def test_grant_requires_exact_object_and_unambiguous_location(location, expected):
    rule = Redirect(
        origin="https://storage.example.invalid",
        path="/files/{id}/sample.pdf",
        required_query=["token"],
    )
    assert redirect_matches(rule, httpx.Headers({"Location": location}), "id", "alice") is expected


def test_duplicate_location_cannot_establish_a_grant():
    rule = Redirect(
        origin="https://storage.example.invalid", path="/files/{id}", required_query=["token"]
    )
    value = "https://storage.example.invalid/files/alice?token=fake"
    assert not redirect_matches(
        rule, httpx.Headers([("Location", value), ("Location", value)]), "id", "alice"
    )
