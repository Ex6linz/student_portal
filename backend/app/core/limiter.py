# app/core/limiter.py
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter

# wspólna instancja do ograniczeń
limiter = Limiter(key_func=get_remote_address)

limiterForum = RateLimiter