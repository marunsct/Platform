import os

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine

from matura import Contract


def _pg_url() -> str | None:
    url = os.environ.get("MATURA_TEST_DATABASE_URL")
    if not url:
        return None
    return url.replace("postgres://", "postgresql+asyncpg://", 1).split("?")[0]


@pytest_asyncio.fixture(params=["sqlite", "postgresql"])
async def db(request, tmp_path):
    """A fresh database with the contract tables, as (engine, contract), on SQLite and, when configured, Postgres."""
    if request.param == "sqlite":
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/c.db")
    else:
        url = _pg_url()
        if not url:
            pytest.skip("MATURA_TEST_DATABASE_URL is not set")
        import uuid

        from sqlalchemy import text
        name = "matura_sdk_" + uuid.uuid4().hex[:12]
        admin = create_async_engine(url, isolation_level="AUTOCOMMIT")
        async with admin.connect() as c:
            await c.execute(text(f"CREATE DATABASE {name}"))
        engine = create_async_engine(url.rsplit("/", 1)[0] + "/" + name)
        request.addfinalizer(lambda: None)
    contract = Contract(request.param)
    async with engine.begin() as conn:
        await contract.create(conn)
    yield engine, contract
    await engine.dispose()
    if request.param == "postgresql":
        async with admin.connect() as c:
            await c.execute(text(f"DROP DATABASE IF EXISTS {name} WITH (FORCE)"))
        await admin.dispose()
