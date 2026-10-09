import os
import random
import sys

# Коренева папку проекту щоб імпортувати дані з shared
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from shared.student import (  #Імпорт персональних даних
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

#Вхідні дані
passwords = [
    "Security@2023",
    "pass",
    "MyStr0ng#Key",
    "root",
    "Advanc3d@Pass",
    "user",
    "Protec7!Pass",
    "1234",
    "Elite@Secur1ty",
    "admin123",
    "qqq"
]

criteria = {
    "min_length": 7,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {"pass", "root", "user", "1234", "admin123", "password"}

random_duplic_pass_add = random.sample(range(len(passwords)), 3) #три дублікати щоб додати в кінець початкового списку
for index in random_duplic_pass_add:
    passwords.append(passwords[index])

def is_password_good(password_var_func, all_passwords): #Фунція перевірки паролю
    min_len = criteria["min_length"] #доступ через ключ словника

    if password_var_func in forbidden_passwords or len(password_var_func) < min_len: #Перевірка чи пароль "Заборонений"
        return "Заборонений"

    has_digit = any(char.isdigit() for char in password_var_func) #Перевірка на присутність різних груп символів
    has_upper = any(char.isupper() for char in password_var_func)
    has_special = any(not char.isalnum() for char in password_var_func)

    met_criteria_count = sum([has_digit, has_upper, has_special]) #кількість виконаних критеріїв

    if met_criteria_count == 3: #варіанти якщо пароль відповідає всім критеріям
        is_unique = all_passwords.count(password_var_func) == 1 #перевіряє чи входить в пасвордс як дублікат через бул
        if len(password_var_func) >= min_len + 4 and is_unique: #перевірка на відповідні критерії
            return "Дуже сильний"
        return "Сильний"
    elif met_criteria_count == 2:
        return "Середній"
    else:
        return "Слабкий"

#Вивід результатів
print(f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}")
print("=" * 45)
print(f"| {'Пароль':<18} | {'Рівень надійності':<20} |") #просто для вигляду таблиці
print("=" * 45)

for p in passwords:
    status = is_password_good(p, passwords)
    print(f"| {p:<18} | {status:<20} |")

print("=" * 45)