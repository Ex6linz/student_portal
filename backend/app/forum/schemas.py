from datetime import datetime

from pydantic import BaseModel, Field, constr


# ─────────────────────────  CREATE SCHEMAS  ──────────────────────────
class TopicCreate(BaseModel):
   
    title: constr(min_length=10, max_length=120) = Field(
        ...,
        description="Tytuł nowego tematu (10–120 znaków)."
    )
    content: constr(min_length=20) = Field(
        ...,
        description="Treść pierwszego posta (min. 20 znaków)."
    )


class PostCreate(BaseModel):
    
    content: constr(min_length=1) = Field(
        ...,
        description="Treść posta (min. 1 znak)."
    )


# ───────────────────────────  READ SCHEMAS  ───────────────────────────
class TopicRead(BaseModel):
    id: int
    title: str
    author_id: int
    created_at: datetime

    class Config:
        orm_mode = True          # konwersja z obiektów SQLAlchemy → JSON-ready


class PostRead(BaseModel):
    id: int
    topic_id: int
    author_id: int
    content: str
    created_at: datetime

    class Config:
        orm_mode = True

class TopicReadWithPosts(TopicRead):
    posts: List[PostRead] = []
    class Config:
        orm_mode = True