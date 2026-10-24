# МікроТік-аудит

Read-only перевірка власного RouterOS: версія, служби, користувачі, firewall input, індикатори з бюлетеня вересня 2026. Скрипт не змінює конфігурацію і не містить експлойтів. На пристрій іде лише фіксований список команд читання через системний OpenSSH.

## Запуск

Потрібні Python 3.10+ і клієнт OpenSSH. Обидва файли `mikrotik_audit.py` і `cve_catalog.py` лежать в одній теці.

```bash
python3 mikrotik_audit.py --update-cve
python3 mikrotik_audit.py --host 192.0.2.1 --user audit --known-hosts ~/.ssh/known_hosts \
  --untrusted-interface ether1 --trusted-network 192.0.2.0/24
python3 mikrotik_audit.py --offline snapshot.json --no-cve-update
```

`--host` сам оновлює каталог, якщо файлу немає або йому більше `--cve-max-age` днів (типово 7). `--update-cve` оновлює завжди; без `--host` після запису завершує роботу. `--no-cve-update` і `--offline` мережу каталогу не чіпають. Ключ NVD, якщо він є, читається лише зі змінної `NVD_API_KEY`.

## Каталог CVE

Файл `cve_catalog.json` зберігається поруч зі скриптом. Джерело оновлення — NVD CVE API 2.0, вибірка `cpe:2.3:o:mikrotik:routeros`. У каталог потрапляють лише CPE продукту RouterOS: апаратні рядки ігноруються, точна версія в CPE лишається точною, діапазон без меж не робить усі релізи вразливими автоматично.

Вбудована підлога для шести CVE бюлетеня 2026-10-06 додається при кожному читанні. Завантажений файл може додати CVE і розширити діапазон, але не може оголосити 7.24.2 або 7.23.4 виправленими для CVE-2026-67278. Повна латка цього бюлетеня: 7.24.3, 7.23.6, 6.49.21 і новіші стабільні релізи гілки. Якщо NVD дав лише верхню межу, каталог вважає вразливими всі старіші номери версій: так 6.49.21 лишається в переліку для окремих CVE 2022 і 2025 років, хоча вересневий бюлетень 2026 для нього закритий.

NVD не кодує гілку 7.25.0 beta. Для п’яти CVE, закритих у 7.25.0 beta 3, збірка нижче 3 лишається вразливою, збірка 3 і вище — ні. Для CVE-2026-67278 будь-яка бета або rc 7.25.0 лишається непідтвердженою. Бета самої версії-латки (наприклад 7.24.3beta) ще вразлива: вона менша за стабільний реліз.

Вердикт версії будується лише з записів, де межі вдалося прочитати. CVE без меж або з нечисловою межею лишаються в знахідці `CVE-NO-RANGE` і не перетворюють латаний реліз на вразливий.

Каталог не доводить доступність з мережі, не замінює бюлетень, якого ще немає в NVD, і не є доказом відсутності компрометації.

## Перевірки

```bash
python3 -m venv .venv
.venv/bin/pip install pytest ruff mypy
.venv/bin/ruff check cve_catalog.py tests
.venv/bin/mypy cve_catalog.py
.venv/bin/pytest
```

| Вимога | Модуль | Тест |
|---|---|---|
| Межі бюлетеня 2026-10-06, включно з неповною латкою 7.24.2 / 7.23.4 | `cve_catalog.py` | `tests/test_cve_catalog.py`, `tests/test_version_assessment.py` |
| Автооновлення NVD у файл поруч зі скриптом, без звуження підлоги | `cve_catalog.py`, `prepare_catalog` | `test_update_normalizes_nvd_and_paginates`, `test_narrowed_file_cannot_drop_the_floor`, `test_update_only_writes_beside_the_script` |
| Збій завантаження не затирає наявний файл | `update_catalog` | `test_empty_feed_does_not_replace_catalog` |
| Каталог не потрапляє в команду RouterOS | `collection_command` | `test_remote_command_does_not_carry_the_catalog` |
