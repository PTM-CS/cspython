import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, List, Optional, Set

PBKDF2_ITERATIONS = 100_000 #ітерації для сповільнення (для захисту від брутфорсу)
SESSION_TIMEOUT_SEC = 900 #тривалість сесії в секундах після чого її термінують

EMAIL_REGEX = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+$") # проста перевірка емейлу на рівні input validation
class User:
    def __init__( #конструктор ініт
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
        active: bool = True,
    ):
        self.username = username #відкрито
        self._email = "" #захист через _
        self.email = email #запускає сетер який перевіряє
        self.role = role
        self.active = active

        self.__password_salt = b"" #приватні атрибути
        self.__password_hash = b""
        self.set_password(password) #пароль не зберігається в відкритому вигляді виклик хешування

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str):
        if not EMAIL_REGEX.match(value): #поверхнева перевірка на присутність посторонніх символів
            raise ValueError(f"Неправильний формат email: '{value}'")
        self._email = value

    def set_password(self, password: str):
        self.__password_salt = os.urandom(16) # генерує випадкову сіль і зберігає хеш пароля
        self.__password_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS)

    def check_password(self, password: str) -> bool:
        if not self.active:
            return False

        calculated_hash = hashlib.pbkdf2_hmac(      # Перевіряє відповідність пароля через hmac.compare_digest
            "sha256", password.encode("utf-8"), self.__password_salt, PBKDF2_ITERATIONS)
        return hmac.compare_digest(self.__password_hash, calculated_hash) # виконує порівняння за постійний час
                                                                          # щоб не можна підбирати по часі (проста перевірка покаже що
    def deactivate(self):                                                 # перший байт неправильний і надішле відповідь швидше
        self.active = False  # блокування акаунта без видалення з системи

    def __str__(self):
        status = "Active" if self.active else "Inactive"
        return (
            f"User(username='{self.username}', role='{self.role}', status='{status}')") #вигляд під час виклику прінт

class Admin(User):  # наслідування від User
    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "admin",
        active: bool = True,
        permissions: Optional[Set[str]] = None,
    ):
        super().__init__(username, email, password, role=role, active=active)
        self.permissions = set(permissions) if permissions is not None else set() # set() щоб не передавати змінювану
                                                                                  # колекцію як аргумент за замовчуванням
    def grant_permission(self, permission: str):
        self.permissions.add(permission)  # додає дозвіл

    def revoke_permission(self, permission: str):
        self.permissions.discard(permission) # через діскард щоб не було кі ерор

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions  # перевірка чи є дозвіл

    def __str__(self):
        perms = ", ".join(sorted(self.permissions)) if self.permissions else "None"
        return f"{super().__str__()} [Perms: {perms}]"  #отримує базовий рядок юзера і додає права в кінці

class Session:
    def __init__(self, ip: str):
        self.ip = ip
        now = datetime.now(timezone.utc)  # без багів локального часу
        self.login_time = now
        self.last_activity = now

    def touch(self):
        self.last_activity = datetime.now(timezone.utc) #оновлює час

    def is_active(self, timeout_sec: int) -> bool:
        if timeout_sec <= 0:
            raise ValueError("Таймаут має бути > 0") #анулює сесію
        return (datetime.now(timezone.utc) - self.last_activity) < timedelta(
            seconds=timeout_sec)

@dataclass
class AuditEntry:  # декоратор створює код для даних автоматично
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    def __init__(self):
        self._entries: List[AuditEntry] = []

    def add_log(self, username: str, action: str): #створення нового запису і додавання його в кінець списку
        self._entries.append(AuditEntry(datetime.now(timezone.utc), username, action))

    def show_all(self) -> List[AuditEntry]:
        return list(self._entries)


class UserAccount:  # композиція. об'єднує User, Session, AuditLog
    def __init__(self, user: User, audit_log: Optional[AuditLog] = None):
        self.user = user
        self.session: Optional[Session] = None
        self.audit_log = audit_log if audit_log else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if (
            self.user.username != username
            or not self.user.active
            or not self.user.check_password(password)
        ):
            self.audit_log.add_log(username, "login_failure") #додає логи як результат логіна
            return False

        self.session = Session(ip=ip)
        self.audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if not self.session:
            return False
        return self.session.is_active(SESSION_TIMEOUT_SEC) #перевірка наявності сесії і таймауту

    def logout(self):
        if self.session:
            self.audit_log.add_log(self.user.username, "logout")
            self.session = None

    # маг методи для доступу через словник account["user"]
    def __getitem__(self, key: str) -> Any:
        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit_log":
            return self.audit_log
        raise KeyError(f"Невідомий ключ: {key}")

    def __setitem__(self, key: str, value: Any):
        if key == "user" and isinstance(value, User):
            self.user = value
        elif key == "session" and (value is None or isinstance(value, Session)):
            self.session = value
        elif key == "audit_log" and isinstance(value, AuditLog): self.audit_log = value
        else: raise TypeError(f"Неправильний тип або ключ '{key}'")