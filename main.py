import base64
import hashlib
from datetime import datetime
import psycopg2
import yaml
import os
import secrets
import string

# Default PAT scopes as a YAML string
default_scopes = """---
- api
- read_user
- read_api
- read_repository
- write_repository
- read_registry
- write_registry
- sudo
"""

# Environment variable retrieval
rails_secret_content = os.environ.get('RAILS_SECRET_CONTENT')  # Base64 encoded YAML content
pg_host = os.environ.get('PG_HOST')
pg_dbname = os.environ.get('PG_DBNAME')
pg_port = os.environ.get('PG_PORT')
pg_username = os.environ.get('PG_USERNAME')
pg_password = os.environ.get('PG_PASSWORD')
api_key = os.environ.get('API_KEY')
user_id = int(os.environ.get('USER_ID', 1))
user_scopes = os.environ.get('USER_SCOPES', default_scopes)
api_name = os.environ.get('API_NAME', "Managed by CINAQ gitlab-personal-access-token")
rails_secrets = yaml.safe_load(rails_secret_content)
db_key_base = rails_secrets['production']['db_key_base']

api_key = os.environ.get('API_KEY', '').strip()
# Validation for API_KEY length
if len(api_key) != 20:
    print(len(api_key))
    print(api_key)
    raise Exception("API_KEY must be exactly 20 characters long")


def generate_pat(api_key):
    # Generate a unique part to append to the api_key, ensuring the overall length is 20
    unique_part = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20))
    return api_key + unique_part


# New function to simulate generating a token (Modify this logic as needed)
def generate_token(api_key, db_key_base):
    token = generate_pat(api_key)  # This would be the actual PAT you use
    token_digest = base64.b64encode(hashlib.sha256((token + db_key_base[:32]).encode('utf-8')).digest()).decode('utf-8')
    return token, token_digest


token, token_digest = generate_token(api_key, db_key_base)


def get_id(conn, user_id, token_digest):
    with conn.cursor() as cursor:
        cursor.execute(
            """SELECT id FROM personal_access_tokens WHERE user_id = %s and token_digest = %s""",
            (user_id, token_digest,)
        )
        row = cursor.fetchone()
        if row:
            return row[0]
        else:
            return None


def create_pat(conn, user_id, user_scopes, token_digest):
    with conn.cursor() as cursor:
        now = datetime.now()
        cursor.execute(
            """INSERT INTO personal_access_tokens
                (name, impersonation, scopes, revoked, user_id, token_digest, created_at, updated_at, expire_notification_delivered, after_expiry_notification_delivered)
                VALUES  (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (api_name, False, user_scopes, False, user_id, token_digest, now, now, False, False)
        )


connect_str = f"dbname='{pg_dbname}' user='{pg_username}' host='{pg_host}' password='{pg_password}' port='{pg_port}'"
conn = psycopg2.connect(connect_str)

current_id = get_id(conn, user_id, token_digest)
if not current_id:
    create_pat(conn, user_id, user_scopes, token_digest)
new_id = get_id(conn, user_id, token_digest)
if not new_id:
    raise Exception("Failed to create PAT")
else:
    print("PAT ID: " + str(new_id))
    print("Personal Access Token (PAT):", token)
conn.commit()
conn.close()
