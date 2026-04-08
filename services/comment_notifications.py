"""Create comments and fan-out @mention notifications."""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from db.models import Comment
from db.repo import CommentRepository, NotificationRepository
from services.auth import load_rbac_config
from services.mentions import resolve_mentions


def add_comment_with_notifications(
    db: Session,
    *,
    entity_type: str,
    entity_id: int,
    use_case_id: Optional[int],
    author: str,
    body: str,
) -> Comment:
    users = set(load_rbac_config().get("users", {}).keys())
    mentions = resolve_mentions(body, users)
    c = CommentRepository.create(
        db,
        entity_type=entity_type,
        entity_id=entity_id,
        use_case_id=use_case_id,
        author=author,
        body=body.strip(),
        mentions=mentions,
    )
    preview = (body.strip()[:120] + "…") if len(body.strip()) > 120 else body.strip()
    for u in mentions:
        if u == author:
            continue
        NotificationRepository.create(
            db,
            username=u,
            message=f"{author} mentioned you on {entity_type} #{entity_id}: {preview}",
            entity_type=entity_type,
            entity_id=entity_id,
            comment_id=c.id,
        )
    return c
