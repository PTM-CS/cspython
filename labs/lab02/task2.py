import argparse
import json
import logging
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))) # Коренева папка проекту
try:
    from shared.student import (
        GROUP_NAME,
        STUDENT_NAME,
        VARIANT_NUMBER,
    )
except ImportError:
    STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER = "Student", "Group", 1

logging.basicConfig( # налаштування логування (формат часу та повідомлень)
    level=logging.INFO, format="[%(levelname)s] %(message)s")

logger = logging.getLogger(__name__)

DEFAULT_LOG_PATH = os.path.join(
    os.path.dirname(__file__), "data", "auth.log") # шляхи та константи
DEFAULT_JSON_PATH = os.path.join(
    os.path.dirname(__file__), "data", "blocklist_ips.json")

# вираз для парсингу подій Failed / Accepted password
# враховує випадки "Failed password for admin" та "Failed password for invalid user test"
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<action>Failed|Accepted)\s+password\s+(?:for\s+(?:invalid\s+user\s+)?(?P<username>\S+))\s+"
    r"from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+\d+")

def parse_timestamp(ts_str: str, current_year: int) -> datetime: # рядок часу системного журналу ('Sep 27 14:00:00') у datetime
    clean_ts = re.sub(r"\s+", " ", ts_str)
    full_ts_str = f"{current_year} {clean_ts}"     # заміна множинних пробілів на поодинокі для правильного parsing (для днів 1-9)
    return datetime.strptime(full_ts_str, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)

def analyze_auth_log(     # головна функція для аналізу лог-файлу SSH та виявлення Bruteforce-атак
    log_path: str, threshold: int, window_min: int, output_json: str
):
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант:"
        f" {VARIANT_NUMBER}")
    print("=" * 60)
    print("УТИЛІТА АНАЛІЗУ СБРОЙОВИХ СПРОБ ВХОДУ SSH (BRUTEFORCE DETECTION):\n")

    if not os.path.exists(log_path): #перевірка чи є файл
        logger.error(f"Файл логів не знайдено за шляхом: {log_path}")
        return

    logger.info(f"Analyzing authentication events in {log_path}...")

    failed_attempts = defaultdict(list)  # для створення списку автоматично для айпі якого не було в словнику через дефдікт
    accepted_attempts = defaultdict(list)  # ip -> list of (timestamp, username)

    total_lines = 0
    parsed_lines = 0 # лічильники
    timestamps = []
    current_year = datetime.now(timezone.utc).year

    try:
        with open(log_path, "r", encoding="utf-8") as f: # читання і парсинг файлу
            for line in f: #читає по рядку а не завантажує весь файл в оперативку
                total_lines += 1
                match = LOG_PATTERN.search(line) # накладає регекс
                if match:
                    parsed_lines += 1
                    data = match.groupdict()
                    ts = parse_timestamp(data["timestamp"], current_year)
                    timestamps.append(ts)

                    action = data["action"]
                    ip = data["ip"]
                    username = data["username"] # підготовка даних щоб їх можна були використвовувати в нормальному вигляді

                    if action == "Failed":
                        failed_attempts[ip].append((ts, username))
                    elif action == "Accepted":
                        accepted_attempts[ip].append((ts, username))

        if timestamps:
            time_start = min(timestamps).strftime("%Y-%m-%d %H:%M:%S")
            time_end = max(timestamps).strftime("%Y-%m-%d %H:%M:%S")
            logger.info(f"Processed {total_lines} lines (Time range: {time_start} -"
                f" {time_end})") # підсумки парсингу
        else:
            logger.info(f"Processed {total_lines} lines (No matching auth events"
                " found).")

        print("=== SSH Bruteforce Detection Results ===")
        print(
            f"Failed Attempts Threshold: >{threshold} attempts in"
            f" {window_min} minutes\n")

        detected_bruteforce = {}
        blocklist_ips = []

        # за часовим вікном
        window_delta = timedelta(minutes=window_min)

        for ip, attempts in failed_attempts.items():
            attempts.sort(key=lambda x: x[0])       # сорт за часом
            total_failures = len(attempts)
            target_users = sorted({user for _, user in attempts})

            is_bruteforce = False

            for i in range(len(attempts)): # перевірка наявності > threshold спроб за window_min хвилин
                start_time = attempts[i][0]
                count_in_window = sum(   # рахує кількість спроб у часовому вікні
                    1
                    for t, _ in attempts
                    if start_time <= t <= start_time + window_delta)

                if count_in_window > threshold:
                    is_bruteforce = True
                    break

            if is_bruteforce:             # якщо виявлено підбір паролів
                blocklist_ips.append(ip)
                users_str = ", ".join(target_users)

                alert_msg = (
                    f"Bruteforce Detected! IP: {ip:<15} | Total Failures:"
                    f" {total_failures:<3} | Target Users: {users_str}"                )

                logger.error(f"[ALERT] {alert_msg}") # логування помилки/попередження через logger.error

                detected_bruteforce[ip] = {
                    "total_failures": total_failures,
                    "target_users": target_users, # досьє брутфорс айпішок
                    "first_seen": attempts[0][0].strftime("%Y-%m-%d %H:%M:%S"),
                    "last_seen": attempts[-1][0].strftime(
                        "%Y-%m-%d %H:%M:%S"),
                }

        print("\n=== Recommended Blocklist (IPs) ===")  # формування рекомендованого списку блокування
        if blocklist_ips:
            for ip in blocklist_ips:
                print(ip)
        else:
            print("No IPs meet the threshold criteria for blocking.")

        output_data = {         # експорт у JSON файл
            "analysis_metadata": {
                "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "threshold": threshold,
                "window_minutes": window_min,
                "total_lines_analyzed": total_lines,
            },
            "blocklist_ips": blocklist_ips,
            "details": detected_bruteforce,
        }

        os.makedirs(os.path.dirname(output_json), exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as json_file: # кожен раз повнсітю перезаписує жсон бо він робить це тільки
            json.dump(output_data, json_file, indent=4, ensure_ascii=False)  #на основі даного лог аут

        print("-" * 60)
        logger.info(f"Exported blocklist to {output_json}.")

    except FileNotFoundError as e:
        logger.error(f"Помилка файлу: {e}")     # обробка винятків
    except PermissionError as e:
        logger.error(f"Помилка прав доступу: {e}")
    except Exception as e:  # noqa: BLE001
        logger.error(f"Невідома помилка під час аналізу логів: {e}")


def main():
    parser = argparse.ArgumentParser(     # обробка CLI аргументів при прямому запуску task2.py
        description="SSH / Linux Auth Log Bruteforce Detector")
    parser.add_argument(
        "--auth-log",
        type=str,
        default=DEFAULT_LOG_PATH,
        help="Шлях до файлу auth.log",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Поріг невдалих спроб (дефолт: 5)",
    )
    parser.add_argument(
        "--window-min",
        type=int,
        default=5,
        help="Часове вікно в хвилинах (дефолт: 5)",
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default=DEFAULT_JSON_PATH,
        help="Шлях для збереження JSON звіту",
    )

    args = parser.parse_args()
    analyze_auth_log(
        args.auth_log, args.threshold, args.window_min, args.output_json)

if __name__ == "__main__":
    main()