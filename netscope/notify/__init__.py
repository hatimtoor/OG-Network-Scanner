"""Notification backends (desktop, email, webhook)."""
from .dispatcher import notify, send_html_email

__all__ = ["notify", "send_html_email"]
