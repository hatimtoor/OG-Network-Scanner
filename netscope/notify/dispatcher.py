"""Fan-out notifications to every configured backend.

All backends are best-effort and never raise into the caller — a failed
notification must not break scanning.
"""
from __future__ import annotations

import smtplib
import subprocess
import sys
from email.mime.text import MIMEText

from ..config import settings


def _notify_desktop(title: str, message: str) -> None:
    if not settings.notify_desktop:
        return
    try:
        if sys.platform.startswith("win"):
            # Toast via PowerShell BurntToast is not guaranteed; use a
            # dependency-free balloon through msg is unreliable, so we use a
            # simple non-blocking PowerShell notification.
            ps = (
                "powershell", "-NoProfile", "-Command",
                "[void][System.Reflection.Assembly]::LoadWithPartialName("
                "'System.Windows.Forms');"
                f"$n=New-Object System.Windows.Forms.NotifyIcon;"
                "$n.Icon=[System.Drawing.SystemIcons]::Information;"
                "$n.Visible=$true;"
                f"$n.ShowBalloonTip(6000,'{title}','{message}',"
                "[System.Windows.Forms.ToolTipIcon]::Info)"
            )
            subprocess.Popen(ps, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "darwin":
            script = f'display notification "{message}" with title "{title}"'
            subprocess.Popen(["osascript", "-e", script])
        else:
            subprocess.Popen(["notify-send", title, message])
    except Exception:
        pass


def _notify_email(title: str, message: str) -> None:
    if not (settings.smtp_host and settings.smtp_to):
        return
    try:
        msg = MIMEText(message)
        msg["Subject"] = f"[NetScope] {title}"
        msg["From"] = settings.smtp_user or "netscope@localhost"
        msg["To"] = settings.smtp_to
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
            server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_pass)
            server.send_message(msg)
    except Exception:
        pass


def _notify_webhook(title: str, message: str) -> None:
    if not settings.webhook_url:
        return
    try:
        import requests

        url = settings.webhook_url
        # Telegram bot URLs use a different payload shape than Discord/Slack.
        if "api.telegram.org" in url:
            requests.post(url, json={"text": f"*{title}*\n{message}"}, timeout=10)
        else:
            requests.post(url, json={"content": f"**{title}**\n{message}"}, timeout=10)
    except Exception:
        pass


def send_html_email(subject: str, html: str, to: str = "") -> bool:
    """Send an HTML email (used for scheduled reports). Returns success."""
    recipient = to or settings.report_email or settings.smtp_to
    if not (settings.smtp_host and recipient):
        return False
    try:
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.smtp_user or "netscope@localhost"
        msg["To"] = recipient
        msg.attach(MIMEText(html, "html"))
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
            server.starttls()
            if settings.smtp_user:
                server.login(settings.smtp_user, settings.smtp_pass)
            server.send_message(msg)
        return True
    except Exception:
        return False


def notify(title: str, message: str) -> None:
    """Send a notification through all configured channels."""
    _notify_desktop(title, message)
    _notify_email(title, message)
    _notify_webhook(title, message)
