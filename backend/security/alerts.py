import json
import mimetypes
import os
import smtplib
import ssl
import urllib.parse
import urllib.request
from email.message import EmailMessage


def show_local_popup(message, title="Sentinel Security Alert"):
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, str(message), str(title), 0x1000)
        return True, "popup"
    except Exception as exc:
        return False, f"popup_failed:{exc}"


def play_local_alarm():
    try:
        import winsound

        winsound.MessageBeep(winsound.MB_ICONHAND)
        winsound.Beep(1200, 280)
        winsound.Beep(980, 320)
        return True, "alarm"
    except Exception as exc:
        return False, f"alarm_failed:{exc}"


def send_email_alert(email_config, subject, body, attachment_path=None):
    if not email_config or not email_config.get("enabled"):
        return False, "email_disabled"

    required = [
        "smtp_server",
        "smtp_port",
        "username",
        "password",
        "from_email",
        "to_email",
    ]
    if any(not email_config.get(key) for key in required):
        return False, "email_incomplete"

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = email_config["from_email"]
    message["To"] = email_config["to_email"]
    message.set_content(body)

    if attachment_path and os.path.exists(attachment_path):
        mime_type, _encoding = mimetypes.guess_type(attachment_path)
        maintype, subtype = (mime_type or "application/octet-stream").split("/", 1)
        with open(attachment_path, "rb") as handle:
            message.add_attachment(
                handle.read(),
                maintype=maintype,
                subtype=subtype,
                filename=os.path.basename(attachment_path),
            )

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP(email_config["smtp_server"], int(email_config["smtp_port"])) as server:
            server.starttls(context=context)
            server.login(email_config["username"], email_config["password"])
            server.send_message(message)
        return True, "email"
    except Exception as exc:
        return False, f"email_failed:{exc}"


def send_telegram_alert(telegram_config, message, attachment_path=None):
    if not telegram_config or not telegram_config.get("enabled"):
        return False, "telegram_disabled"

    token = telegram_config.get("bot_token")
    chat_id = telegram_config.get("chat_id")
    if not token or not chat_id:
        return False, "telegram_incomplete"

    try:
        if attachment_path and os.path.exists(attachment_path):
            url = f"https://api.telegram.org/bot{token}/sendPhoto"
            boundary = "----SentinelSecurityBoundary"
            with open(attachment_path, "rb") as handle:
                photo_bytes = handle.read()

            parts = [
                f"--{boundary}\r\n".encode("utf-8"),
                b'Content-Disposition: form-data; name="chat_id"\r\n\r\n',
                f"{chat_id}\r\n".encode("utf-8"),
                f"--{boundary}\r\n".encode("utf-8"),
                b'Content-Disposition: form-data; name="caption"\r\n\r\n',
                f"{message}\r\n".encode("utf-8"),
                f"--{boundary}\r\n".encode("utf-8"),
                (
                    f'Content-Disposition: form-data; name="photo"; filename="{os.path.basename(attachment_path)}"\r\n'
                    "Content-Type: image/jpeg\r\n\r\n"
                ).encode("utf-8"),
                photo_bytes,
                b"\r\n",
                f"--{boundary}--\r\n".encode("utf-8"),
            ]
            payload = b"".join(parts)
            request = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            )
        else:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            payload = urllib.parse.urlencode({"chat_id": chat_id, "text": message}).encode("utf-8")
            request = urllib.request.Request(url, data=payload)

        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
        return True, "telegram"
    except Exception as exc:
        return False, f"telegram_failed:{exc}"


def dispatch_security_alerts(config, message, attachment_path=None, metadata=None):
    actions = []
    alert_config = (config or {}).get("alerts", {})

    if alert_config.get("popup", True):
        ok, label = show_local_popup(message)
        actions.append(label if ok else label)

    if alert_config.get("sound", True):
        ok, label = play_local_alarm()
        actions.append(label if ok else label)

    subject = "Sentinel Security Alert"
    body_lines = [message]
    if metadata:
        body_lines.append("")
        body_lines.append("Metadata:")
        body_lines.append(json.dumps(metadata, ensure_ascii=False, indent=2))
    body = "\n".join(body_lines)

    ok, label = send_email_alert(alert_config.get("email", {}), subject, body, attachment_path)
    if label != "email_disabled":
        actions.append(label if ok else label)

    ok, label = send_telegram_alert(alert_config.get("telegram", {}), message, attachment_path)
    if label != "telegram_disabled":
        actions.append(label if ok else label)

    return actions
