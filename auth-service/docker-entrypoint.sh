#!/bin/bash
set -e

echo "Checking database access..."
if [ -f "$DB_PATH" ]; then
    echo "Database file found at: $DB_PATH"
    
    # Verify SQLite access
    if sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users;" > /dev/null 2>&1; then
        echo "Successfully connected to database"
        echo "Current user count: $(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users;")"
    else
        echo "Error: Cannot access database. Check permissions and file integrity"
        exit 1
    fi
else
    echo "Error: Database file not found at $DB_PATH"
    exit 1
fi

# Execute the main command
exec "$@"