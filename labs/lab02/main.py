import argparse
import os
import sys

# коренева для імпорту з шейрд
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
try:
    from shared.student import (
        GROUP_NAME,
        STUDENT_NAME,
        VARIANT_NUMBER,
    )
except ImportError:
    STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER = "Student", "Group", 1

from labs.lab02.task1 import Admin, AuditLog, User, UserAccount

def run_demo():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант:"
        f" {VARIANT_NUMBER}")
    print("=" * 60)
    print("ЗАВДАННЯ 1:\n")

    try:
        audit = AuditLog()
        print("СТВОРЕННЯ КОРИСТУВАЧІВ:")   #створення обєктів
        user1 = User(
            username="user1",
            email="user1@lpnu.ua",
            password="RightPass123!",
        )
        admin1 = Admin(
            username="admin1",
            email="admin1@lpnu.ua",
            password="AdminPass456!",
        )

        print(
            f"| {user1.username:<12} | {user1.email:<25} | Role: {user1.role}")
        print(
            f"| {admin1.username:<12} | {admin1.email:<25} | Role:"
            f" {admin1.role}")
        print("-" * 60)

        print("КЕРУВАННЯ ПРАВАМИ АДМІНІСТРАТОРА:") #керування правами
        admin1.grant_permission("READ_LOGS")
        admin1.grant_permission("MANAGE_USERS")
        print(f"Адмін після додавання прав: {admin1}")
        admin1.revoke_permission("MANAGE_USERS")
        print(
            "Чи має право 'READ_LOGS'?  ->"
            f" {'ALLOW' if admin1.has_permission('READ_LOGS') else 'DENY'}")
        print("-" * 60)

        print("ТЕСТУВАННЯ ВАЛІДАЦІЇ EMAIL:") #валідація емейл
        try:
            user1.email = "12invalid@lpnu.ua"
        except ValueError as e:
            print(f"Очікувана помилка (цифра на початку): {e}")

        user1.email = "user1@lpnu.ua"
        print(f"Успішно змінено email на: {user1.email}")
        print("-" * 60)

        print("ТЕСТУВАННЯ ВХОДУ (LOGIN):") #приклад аунтентифікації
        account = UserAccount(user=user1, audit_log=audit)

        test_cases = [
            ("user1", "wrongpas", "192.168.1.50"),
            ("admin1", "RightPass123!", "192.168.1.50"),]

        for u, p, ip in test_cases:
            is_success = account.login(u, p, ip)
            print(
                f"User={u:<10} IP={ip:<15} ->"
                f" {'ALLOW' if is_success else 'DENY (Wrong auth)'}")
        print("-" * 60)

        print("ДОСТУП ЧЕРЕЗ СЛОВНИК (__getitem__):")
        print(f"account['user']    -> {account['user'].username}")
        print(
            "account['session'] ->"
            f" {account['session'].ip if account['session'] else 'None'}")
        print("-" * 60)

        print("ЗАВЕРШЕННЯ СЕАНСУ (LOGOUT):") #логаут
        account.logout()
        print(
            "Статус автентифікації після logout:"
            f" {'ACTIVE' if account.is_authenticated() else 'INACTIVE'}")
        print("-" * 60)

        print("ЖУРНАЛ АУДИТУ:")
        for entry in audit.show_all():
            ts = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC") #аудит
            print(
                f"| {ts} | User: {entry.username:<10} | Action: {entry.action}")

    except Exception as e:  # noqa: BLE001
        print(f"Невідома помилка: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Lab 02 Cybersecurity Tool Suite")
    subparsers = parser.add_subparsers(
        dest="command", help="Команда для виконання (demo або analyze)")

    subparsers.add_parser("demo", help="Запустити демонстрацію Завдання 1 (ООП)") # Команда demo завдання 1


    analyze_parser = subparsers.add_parser(
        "analyze", help="Запустити парсер логів (Завдання 2)") # команда analyze завдання 2
    analyze_parser.add_argument(
        "--auth-log",
        type=str,
        default=os.path.join(os.path.dirname(__file__), "data", "auth.log"),
    )
    analyze_parser.add_argument("--threshold", type=int, default=5)
    analyze_parser.add_argument("--window-min", type=int, default=5)
    analyze_parser.add_argument(
        "--output-json",
        type=str,
        default=os.path.join(
            os.path.dirname(__file__), "data", "blocklist_ips.json"
        ),
    )

    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
    elif args.command == "analyze":
        from labs.lab02.task2 import analyze_auth_log

        analyze_auth_log(
            args.auth_log, args.threshold, args.window_min, args.output_json
        )
    else:
        parser.print_help()


if __name__ == "__main__":
    main()