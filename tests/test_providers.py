import pytest

from dangl3.providers import identify_providers


@pytest.mark.parametrize("target, provider_id", [
    ("OWNER.GITHUB.IO.", "github_pages"),
    ("my-bucket.s3-website-us-east-1.amazonaws.com", "aws_s3_website"),
    ("my.bucket.s3-website.eu-central-1.amazonaws.com", "aws_s3_website"),
    ("app.azurewebsites.net", "azure_app_service"),
    ("name.herokuapp.com", "heroku"), ("name.herokudns.com", "heroku"),
    ("cname.vercel-dns.com", "vercel"), ("project.vercel.app", "vercel"),
    ("site.netlify.app", "netlify"),
])
def test_identifies_provider(database, target, provider_id):
    assert [p.id for p in identify_providers([target], database)] == [provider_id]


@pytest.mark.parametrize("target", [
    "github.io.attacker.example", "fakegithub.io", "github.io", "foo-github.io",
    "github.io.example.com", "herokuapp.com.evil.example", "evilnetlify.app",
    "bucket.s3.amazonaws.com", "bucket.amazonaws.com", "s3-website-us-east-1.amazonaws.com",
    "bucket.s3-website-invalid.amazonaws.com", "app.azurewebsites.net.evil.example",
    "bucket.s3-website.us-east-1.amazonaws.com", "bucket.s3-website-eu-central-1.amazonaws.com",
    "notvercel-dns.com", "anything.example.com",
])
def test_suffix_false_positives(database, target):
    assert not identify_providers([target], database)


def test_multiple_providers_remain_visible(database):
    assert len(identify_providers(["a.github.io", "b.netlify.app"], database)) == 2
