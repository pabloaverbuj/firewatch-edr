#!/bin/sh
set -e

echo "╔══════════════════════════════════════╗"
echo "║        Firewatch EDR — Backend       ║"
echo "╚══════════════════════════════════════╝"

echo "→ Waiting for database..."
# asyncpg doesn't have a CLI, use pg_isready via python
python -c "
import asyncio, asyncpg, os, sys, time

async def wait():
    url = os.environ['DATABASE_URL'].replace('postgresql+asyncpg', 'postgresql')
    for i in range(30):
        try:
            conn = await asyncpg.connect(url)
            await conn.close()
            print('  Database ready.')
            return
        except Exception as e:
            print(f'  Retrying ({i+1}/30)...')
            await asyncio.sleep(2)
    print('  Database not available after 60s. Exiting.')
    sys.exit(1)

asyncio.run(wait())
"

echo "→ Applying schema..."
python -c "
import asyncio
from app.database import engine
from app.models import Base

async def create():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()
    print('  Schema ready.')

asyncio.run(create())
"

echo "→ Starting server..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
