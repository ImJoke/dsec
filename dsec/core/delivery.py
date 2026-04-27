import logging
import requests
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

class TelegramHandler(DeliveryHandler):
    def deliver(self, message: str, **kwargs):
        token = os.getenv("TELEGRAM_BOT_TOKEN")
        chat_id = os.getenv("TELEGRAM_CHAT_ID")
        if not token or not chat_id:
            logger.warning("Telegram delivery skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
            return False
        
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            resp = requests.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"})
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Telegram delivery failed: {e}")
            return False

class SlackHandler(DeliveryHandler):
    def deliver(self, message: str, **kwargs):
        webhook_url = os.getenv("SLACK_WEBHOOK_URL")
        if not webhook_url:
            logger.warning("Slack delivery skipped: SLACK_WEBHOOK_URL not set.")
            return False
        
        try:
            resp = requests.post(webhook_url, json={"text": message})
            resp.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Slack delivery failed: {e}")
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
