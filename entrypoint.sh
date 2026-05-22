#!/bin/sh
# Copy default policies if the policies directory is empty (first run with mounted volume)
if [ -z "$(ls -A /app/policies 2>/dev/null)" ]; then
  cp -r /app/policies-default/* /app/policies/
fi

# Generate a shared session secret so all uvicorn workers can verify each
# other's cookies.  Without this, each worker creates its own random secret
# and sessions break in multi-worker mode.
if [ -z "$RAMPART_SESSION_SECRET" ]; then
  RAMPART_SESSION_SECRET=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
  export RAMPART_SESSION_SECRET
fi

exec "$@"
