from typing import List

from fastapi import Depends, HTTPException, Path, Body, status, Request, Query, APIRouter
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, asc

from app.core.database import get_session          
from app.forum.models import Topic, Post
from app.auth.deps import get_current_user
from app.auth.models import User
from app.core.limiter import limiterForum
from app.forum.schemas import TopicRead, TopicReadWithPosts, TopicCreate, PostCreate

router = APIRouter(prefix="/forum", tags=["forum"])

PAGE_SIZE = 20


@router.get(
    "/topics",
    response_model=List[TopicRead],
    status_code=status.HTTP_200_OK,
    summary="Lista tematów",
    description="Zwraca 20 tematów na stronę, posortowanych malejąco po dacie utworzenia.",
)
def list_topics(
    page: int = Query(1, ge=1, description="Numer strony (od 1)"),
    db: Session = Depends(get_session),
):
    
    stmt = (
        select(Topic)
        .order_by(desc(Topic.created_at))
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    topics = db.scalars(stmt).all()
    return topics

@router.get(
    "/topics/{id}",
    response_model=TopicReadWithPosts,
    status_code=status.HTTP_200_OK,
    summary="Szczegóły tematu z postami",
)
def topic_detail(
    id: int = Path(..., ge=1, description="ID tematu"),
    db: Session = Depends(get_session),
):

    # Ładujemy temat z eager-loadem postów (selectinload), posortowanych ASC
    stmt = (
        select(Topic)
        .options(
            selectinload(Topic.posts)
            .order_by(asc(Post.created_at))  # wymaga relacji Topic.posts
        )
        .where(Topic.id == id)
    )
    topic: Topic | None = db.scalar(stmt)

    if not topic:
        raise HTTPException(status_code=404, detail="Topic not found")

    return topic

@router.post(
    "/topics",
    status_code=status.HTTP_201_CREATED,
    response_model=TopicRead,
    summary="Utwórz nowy temat",
    description="Wymaga JWT; tytuł 10-120 znaków, treść min 20 znaków.",
    dependencies=[Depends(limiterForum.limit("30/minute"))],
)
def create_topic(
    request: Request,
    payload: TopicCreate = Body(...),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    
    topic = Topic(title=payload.title, author_id=current_user.id)
    db.add(topic)
    db.flush()                        

    
    if hasattr(payload, "content") and payload.content:
        first_post = Post(
            topic_id=topic.id,
            author_id=current_user.id,
            content=payload.content,
        )
        db.add(first_post)

    db.commit()
    db.refresh(topic)
    return topic

@router.post(
    "/topics/{id}/posts",
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj posta do tematu",
    description="Wymaga JWT; treść min. 1 znak.",
    dependencies=[Depends(limiterForum.limit("30/minute"))],
)
def create_post(
    request: Request,
    id: int = Path(..., ge=1, description="ID tematu"),
    payload: PostCreate = Body(...),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):

    topic_exists = db.scalar(select(Topic.id).where(Topic.id == id))
    if not topic_exists:
        raise HTTPException(status_code=404, detail="Topic not found")

    post = Post(
        topic_id=id,
        author_id=current_user.id,
        content=payload.content,
    )
    db.add(post)
    db.commit()
    db.refresh(post)

    return {"id": post.id}