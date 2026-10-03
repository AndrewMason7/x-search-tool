"""Shared test fixtures and sample API v2 responses."""

from typing import Any

import pytest


@pytest.fixture
def sample_search_json() -> dict[str, Any]:
    return {
        "data": [
            {
                "id": "1840000000000000001",
                "text": "Excited to share our new research paper on AI agents! #Python #AI",
                "created_at": "2026-10-02T15:30:00.000Z",
                "author_id": "2244994945",
                "edit_history_tweet_ids": ["1840000000000000001"],
                "public_metrics": {
                    "retweet_count": 142,
                    "reply_count": 35,
                    "like_count": 890,
                    "quote_count": 12,
                    "impression_count": 25400,
                },
            },
            {
                "id": "1840000000000000002",
                "text": "Python 3.13 free-threading is a game changer for multi-core performance.",
                "created_at": "2026-10-02T16:00:00.000Z",
                "author_id": "44196397",
                "edit_history_tweet_ids": ["1840000000000000002"],
                "public_metrics": {
                    "retweet_count": 55,
                    "reply_count": 8,
                    "like_count": 310,
                    "quote_count": 4,
                    "impression_count": 8900,
                },
            },
        ],
        "includes": {
            "users": [
                {
                    "id": "2244994945",
                    "name": "AI Researcher",
                    "username": "airesearcher",
                    "verified": True,
                    "profile_image_url": "https://pbs.twimg.com/profile_images/1/avatar.png",
                },
                {
                    "id": "44196397",
                    "name": "Python Core",
                    "username": "ThePSF",
                    "verified": True,
                },
            ]
        },
        "meta": {
            "newest_id": "1840000000000000002",
            "oldest_id": "1840000000000000001",
            "result_count": 2,
            "next_token": "b26v89c19zqg8o3fo7gesq314yb9l2l4ptqy",
        },
    }


@pytest.fixture
def sample_single_post_json() -> dict[str, Any]:
    return {
        "data": {
            "id": "1840000000000000001",
            "text": "Excited to share our new research paper on AI agents! #Python #AI",
            "created_at": "2026-10-02T15:30:00.000Z",
            "author_id": "2244994945",
            "edit_history_tweet_ids": ["1840000000000000001"],
            "public_metrics": {
                "retweet_count": 142,
                "reply_count": 35,
                "like_count": 890,
                "quote_count": 12,
                "impression_count": 25400,
            },
        },
        "includes": {
            "users": [
                {
                    "id": "2244994945",
                    "name": "AI Researcher",
                    "username": "airesearcher",
                    "verified": True,
                    "profile_image_url": "https://pbs.twimg.com/profile_images/1/avatar.png",
                }
            ]
        },
    }
