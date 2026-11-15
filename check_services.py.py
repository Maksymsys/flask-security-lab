"""Quick connectivity check for Redis and the Telegram bot.

Run it manually: python check_services.py
(It is not a pytest test, so it is named check_services.py, not test.py.)
"""
import os

import redis
import requests
from dotenv import load_dotenv

load_dotenv()

print("--- SYSTEM CHECK ---")

print("\n1. Checking Redis...")
try:
    r = redis.Redis.from_url(
        os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        socket_timeout=3,
    )
    r.ping()
    print("[+] Redis is running and responding!")
except Exception as e:
    print(f"[-] Redis error (it may not be running): {e}")

print("\n2. Checking Telegram...")
token = os.getenv("TELEGRAM_BOT_TOKEN")
chat_id = os.getenv("TELEGRAM_CHAT_ID")

if not token or not chat_id:
    print("[-] TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set in .env")
else:
    try:
        res = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": "Network test"},
            timeout=5,
        )
        if res.status_code == 200:
            print("[+] Telegram accepted the message!")
        else:
            # Do not print the request URL: it contains the bot token
            print(f"[-] Telegram returned HTTP {res.status_code}")
    except requests.RequestException as e:
        # Print only the error type: the full message can include the URL with the token
        print(f"[-] Could not reach Telegram: {type(e).__name__}")
