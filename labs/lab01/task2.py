import sys
import os

# Коренева папку проекту щоб імпортувати дані з shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER #Імпорт персональних даних

#Вхідні дані
users = {
    "ciso_office": {
        "role": "ciso",
        "clearance": 4,
        "department": "Executive",
        "active": True,
    },
    "threat_hunter": {
        "role": "threat_analyst",
        "clearance": 3,
        "department": "Threat Intel",
        "active": True,
    },
    "junior_dev": {
        "role": "junior_developer",
        "clearance": 2,
        "department": "Development",
        "active": True,
    },
    "visitor_acc": {
        "role": "visitor",
        "clearance": 1,
        "department": "Guest",
        "active": True,
    },
    "legacy_sys": {
        "role": "legacy",
        "clearance": 2,
        "department": "Legacy",
        "active": False,
    },
}

resources = [
    ("threat_intelligence", 4),
    ("malware_samples", 3),
    ("coding_guidelines", 2),
    ("visitor_wifi", 1),
    ("strategic_plans", 4),
    ("demo_environment", 1),
    ("risk_assessments", 3),
    ("crypto_keys", 4),
    ("api_documentation", 2),
    ("guest_portal", 1),
]

security_levels = ("Guest", "Employee", "Privileged", "Executive")
blocked_users = {"legacy_sys", "malicious_user", "expired_guest"}

print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
print("=" * 60)

print("СПИСОК РЕСУРСІВ СИСТЕМИ:") #Вивід списку усіх ресурсів з текстовими назвами рівнів безпеки
for res_name, res_level in resources:
    level_name = security_levels[res_level - 1] #починається з 0 тому -1
    print(f"Ресурс: {res_name:<20} | Рівень: {level_name} ({res_level})")

print("=" * 60)
print("ПЕРЕВІРКА ДОСТУПУ:\n")

all_users_to_check = set(users.keys()).union(blocked_users) #всіх юзерів в один вар (бере множину ключів і обєднує з
                                                            #множиною заблокованих (бо це вже є множиною імен)

#Алгоритм перевірки доступу та вивід результатів
for username in sorted(all_users_to_check):
    print(f"--- Аналіз доступу для: {username} ---")

    for res_name, res_level in resources:
        # Логіка перевірки по критеріях (порядок має значення)
        if username not in users:
            status = "DENY (User not found)"
        elif username in blocked_users:
            status = "DENY (User is blocked)"
        elif not users[username]["active"]: #в моєму завданні єдиний інактів одночасно і блокнутий
            status = "DENY (Account inactive)" #перевірка на блок раніше тому воно не виведе неактивність
        elif users[username]["clearance"] >= res_level:
            status = "ALLOW"
        else:
            status = "DENY (Insufficient clearance)"

        print(f"user={username:<15} resource={res_name:<20} -> {status}")
    print("-" * 60)