import logging
import requests  # type: ignore[import-untyped]
import os
from typing import Optional

logger = logging.getLogger(__name__)

class DeliveryHandler:
    def deliver(self, message: str, **kwargs):
        raise NotImplementedError

class ConsoleHandler(DeliveryHandler):
    def deliver(self, message: str, **kwargs):
        # Local console delivery is handled by the main CLI logic
        pass

_HTTP_TIMEOUT = 10.0  # seconds — applies to connect + read


def _redact_url(url: str) -> str:
    """Strip the secret portion from delivery URLs so it doesn't leak via logs."""
    if "/bot" in url:
        # Telegram: https://api.telegram.org/bot<TOKEN>/sendMessage
        return url.split("/bot", 1)[0] + "/bot[REDACTED]/sendMessage"
    if "hooks.slack.com" in url:
        return "https://hooks.slack.com/services/[REDACTED]"
    return "[REDACTED_URL]"


class TelegramHandler(DeliveryHandler):
    def deliver(self, message: str, **kwargs):
        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            logger.warning("Telegram delivery skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
            return False

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            resp = requests.post(
                url,
                json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"},
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            # Never log the full URL — it contains the bot token.
            logger.error(f"Telegram delivery failed ({_redact_url(url)}): {type(e).__name__}: {e}")
            return False


class SlackHandler(DeliveryHandler):
    def deliver(self, message: str, **kwargs):
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Slack delivery skipped: SLACK_WEBHOOK_URL not set.")
            return False

        try:
            resp = requests.post(
                webhook_url,
                json={"text": message},
                timeout=_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            return True
        except Exception as e:
            # Never log the full webhook URL — the URL itself IS the secret.
            logger.error(f"Slack delivery failed ({_redact_url(webhook_url)}): {type(e).__name__}: {e}")
            return False

_HANDLERS = {
    "local": ConsoleHandler(),
    "telegram": TelegramHandler(),
    "slack": SlackHandler()
}

def deliver_to(target: str, message: str):
    handler = _HANDLERS.get(target.lower())
    if handler:
        return handler.deliver(message)
    else:
        logger.warning(f"Unknown delivery target: {target}")
        return False
