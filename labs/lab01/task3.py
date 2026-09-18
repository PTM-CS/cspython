import os
import sys
import csv
import json
import hashlib
import datetime

# Коренева папку проекту щоб імпортувати дані з shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER #Імпорт персональних даних

# Шляхи та константи
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_JSON_PATH = os.path.join(DATA_DIR, "log.json")
PERSONAL_SALT = f"{VARIANT_NUMBER:05d}" #персональна сіль

users_db = [] #база даних

class ValidationError(Exception):
    pass

def generate_hash(password: str, salt: str = "00000") -> str: #Функція хешування
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми.")
    if len(password) < 14:
        raise ValidationError("Довжина пароля менша за 14 символів.")

    return hashlib.sha512((password + salt).encode("utf-8")).hexdigest()

def log_event(func): #логування
    def wrapper(*args, **kwargs):
        log_entry = {
            "event": "login",
            "user": args[0] if args else kwargs.get("username", "unknown"), #два способа виклику логіна через аргі і кваргс
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "args": ["***", "***"],
            "kwargs": {},
        }

        try:
            result = func(*args, **kwargs)
            log_entry["result"] = "success" if result else "failure"
            return result
        except Exception as e:
            log_entry["result"] = f"error ({type(e).__name__})"
            raise
        finally:
            logs = []
            if os.path.exists(LOG_JSON_PATH):
                try:
                    with open(LOG_JSON_PATH, "r", encoding="utf-8") as f:
                        logs = json.load(f) #загружає жсон
                except json.JSONDecodeError:
                    pass
            logs.append(log_entry)
            with open(LOG_JSON_PATH, "w", encoding="utf-8") as f:
                json.dump(logs, f, indent=4) #дамп в жсон

    return wrapper

def create_user(username, password):
    return (username, generate_hash(password, PERSONAL_SALT))

def create_users(users_list):
    os.makedirs(DATA_DIR, exist_ok=True) #створює папку якщо папка є то не викидає помилку
    with open(USERS_CSV_PATH, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerows(
            [create_user(u, p) for u, p in users_list] #записує в цсв
        )

@log_event #фіксує виклики функції для логування
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін та пароль порожні.") #якщо пусто то помилка
    try:
        target_hash = generate_hash(password, PERSONAL_SALT)
        return any(u == username and h == target_hash for u, h in users_db) #перевіряє на хоч один збіг в базі
    except ValidationError:
        return False

def main():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER} | Сіль: {PERSONAL_SALT}\n"
        + "-" * 50
    )

    users_to_register = [(f"user{i}", f"GenericPassword{i:02d}!") for i in range(1, 11)] #Створює кортеж з 10 людей і паролями
                                                                            #в завданні не сказано якими саме мають бути записи
    try:
        create_users(users_to_register)

        global users_db
        with open(USERS_CSV_PATH, "r", encoding="utf-8") as f:
            users_db = list(csv.reader(f))

        print("БАЗА ДАНИХ:")
        for u, h in users_db: #виводить базу даних
            print(f"| {u:<7} | {h[:40]}... |")

        print("\nТЕСТУВАННЯ ВХОДУ:")

        test_cases = [ #приклади спроб автентифікації
            ("user1", "GenericPassword01!"),
            ("user2", "GenericPassword02!"),
            ("user3", "GenericPassword03!"),
            ("user4", "GenericPassword04!"),
            ("user5", "GenericPassword05!"),
            ("user6", "GenericPassword06!"),
            ("user7", "WrongPassword123!"),  #неправильний пароль
            ("user8", "Short1"),  #короткий пароль
            ("user99", "GenericPassword01!"),  #логіна немає в базі даних
            ("user10", "GenericPassword10!"),
        ]

        for u, p in test_cases:
            print(f"{u:<7}: {'ALLOW' if login(u, p) else 'DENY'}") #сама перевірка спроб автентифікаї. без діалогового вікна
                                                                   #але не думаю що це обовязково
        try:
            login("", "")
        except ValueError as e:
            print(f"\nОчікувана помилка: {e}") #приклад помилки якщо порожні

    #обробка винятків
    except FileNotFoundError as e:
        print(f"Помилка файлу: {e}")
    except PermissionError as e:
        print(f"Помилка прав: {e}")
    except OSError as e:
        print(f"Помилка вводу/виводу: {e}")
    except ValidationError as e:
        print(f"Помилка валідації: {e}")
    except ValueError as e:
        print(f"Помилка значення: {e}")
    except Exception as e:
        print(f"Невідома помилка: {e}")

if __name__ == "__main__":
    main()