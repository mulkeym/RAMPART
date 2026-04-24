#!/bin/sh
# Copy default policies if the policies directory is empty (first run with mounted volume)
if [ -z "$(ls -A /app/policies 2>/dev/null)" ]; then
  cp -r /app/policies-default/* /app/policies/
fi
exec "$@"
