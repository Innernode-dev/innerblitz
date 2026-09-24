import asyncio
import aiohttp
import logging
from typing import Optional
from app.database import crud
from app.core.hysteria import is_hysteria_running, restart_hysteria

logger = logging.getLogger("innerblitz.bot")

class TelegramBotManager:
    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._offset = 0

    async def _api_call(self, method: str, payload: dict) -> Optional[dict]:
        token = await crud.get_setting("tg_bot_token", "")
        if not token:
            return None
        url = f"https://api.telegram.org/bot{token}/{method}"
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.error(f"Telegram API call error ({method}): {e}")
        return None

    async def send_message(self, chat_id: str, text: str, parse_mode: str = "HTML") -> bool:
        """Send message to a specific Telegram chat ID."""
        res = await self._api_call("sendMessage", {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": parse_mode
        })
        return bool(res and res.get("ok"))

    async def send_admin_notification(self, text: str) -> bool:
        """Send notification to the configured admin chat ID."""
        enabled = await crud.get_setting("tg_notifications_enabled", "0") == "1"
        chat_id = await crud.get_setting("tg_admin_chat_id", "")
        if not enabled or not chat_id:
            return False
        return await self.send_message(chat_id, text)

    async def send_2fa_otp(self, code: str) -> bool:
        """Send 2FA one-time verification code to admin."""
        chat_id = await crud.get_setting("tg_admin_chat_id", "")
        if not chat_id:
            return False
        msg = f"🔐 <b>InnerBlitz 2FA Login Code:</b>\n\n<code>{code}</code>\n\n<i>Code expires in 5 minutes. If you did not request this, check server security!</i>"
        return await self.send_message(chat_id, msg)

    async def _handle_update(self, update: dict):
        message = update.get("message")
        if not message or not message.get("text"):
            return

        chat_id = str(message["chat"]["id"])
        text = message["text"].strip()
        admin_chat_id = await crud.get_setting("tg_admin_chat_id", "")

        is_admin = (chat_id == admin_chat_id)

        if text.startswith("/start"):
            if not admin_chat_id:
                # Offer to link admin
                await self.send_message(
                    chat_id, 
                    f"👋 <b>Welcome to InnerBlitz Bot!</b>\n\nYour Chat ID is: <code>{chat_id}</code>\n\nEnter this Chat ID in the Web Panel settings to link your admin account!"
                )
            elif is_admin:
                await self.send_message(
                    chat_id,
                    "⚡ <b>InnerBlitz Admin Console</b>\n\nCommands:\n/stats - System and Proxy status\n/users - Active users\n/restart - Restart Hysteria 2"
                )
            else:
                await self.send_message(
                    chat_id,
                    "👋 <b>Welcome!</b> Send your Subscription Token to check your proxy traffic usage and get config."
                )

        elif text.startswith("/stats") and is_admin:
            status_text = "🟢 Active" if is_hysteria_running() else "🔴 Inactive"
            users = await crud.get_all_users()
            msg = (
                f"📊 <b>InnerBlitz Status</b>\n\n"
                f"• Hysteria 2 Core: {status_text}\n"
                f"• Total Users: {len(users)}\n"
            )
            await self.send_message(chat_id, msg)

        elif text.startswith("/restart") and is_admin:
            restart_hysteria()
            await self.send_message(chat_id, "🔄 Hysteria 2 restarted successfully!")

        else:
            # Check if text is a subscription token
            user = await crud.get_user_by_token(text)
            if user:
                used = user.get("used_traffic_gb", 0)
                total = user.get("max_traffic_gb", "Unlimited")
                days = user.get("days_left", "N/A")
                await self.send_message(
                    chat_id,
                    f"👤 <b>User:</b> {user['username']}\n"
                    f"📊 <b>Traffic:</b> {used} GB / {total} GB\n"
                    f"⏳ <b>Days left:</b> {days}\n"
                    f"🔗 <b>Portal:</b> /portal/{user['sub_token']}"
                )

    async def start_polling(self):
        """Long polling loop for Telegram bot commands."""
        self._running = True
        logger.info("Telegram Bot service started.")
        while self._running:
            token = await crud.get_setting("tg_bot_token", "")
            if not token:
                await asyncio.sleep(10)
                continue

            try:
                res = await self._api_call("getUpdates", {
                    "offset": self._offset,
                    "timeout": 20
                })
                if res and res.get("ok"):
                    for update in res.get("result", []):
                        self._offset = update["update_id"] + 1
                        await self._handle_update(update)
            except Exception as e:
                logger.error(f"Telegram polling loop exception: {e}")
                await asyncio.sleep(5)
            await asyncio.sleep(1)

    def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()

tg_bot = TelegramBotManager()
