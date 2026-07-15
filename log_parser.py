
import re


def determine_severity(message):

    message = message.lower()

    if any(keyword in message for keyword in [
        "failed password",
        "authentication failure",
        "unauthorized",
        "brute force",
        "attack",
        "critical"
    ]):
        return "Critical"

    elif any(keyword in message for keyword in [
        "error",
        "denied",
        "invalid user",
        "warning"
    ]):
        return "High"

    elif any(keyword in message for keyword in [
        "notice",
        "login",
        "logout"
    ]):
        return "Medium"

    return "Low"


def detect_event_type(line):

    line = line.lower()

    if "failed password" in line:
        return "Authentication"

    elif "accepted password" in line:
        return "Authentication"

    elif "get " in line or "post " in line:
        return "Web Access"

    elif "error" in line:
        return "System Error"

    elif "ssh" in line:
        return "SSH Access"

    return "General"


def extract_ip(line):

    match = re.search(
        r'(\d{1,3}(?:\.\d{1,3}){3})',
        line
    )

    if match:
        return match.group(1)

    return "Unknown"


def extract_timestamp(line):

    match = re.search(
        r'([A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+)',
        line
    )

    if match:
        return match.group(1)

    return "Unknown"


def parse_log_file(filepath):

    parsed_logs = []

    try:

        with open(
            filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            lines = file.readlines()

            for line in lines:

                timestamp = extract_timestamp(line)

                source_ip = extract_ip(line)

                event_type = detect_event_type(line)

                severity = determine_severity(line)

                parsed_logs.append({

                    "timestamp": timestamp,

                    "source_ip": source_ip,

                    "event_type": event_type,

                    "severity": severity,

                    "message": line.strip()

                })

    except Exception as e:

        print(
            f"Error parsing log file: {e}"
        )

    return parsed_logs