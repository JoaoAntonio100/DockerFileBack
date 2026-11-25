import os
import re
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import bcrypt
import jwt
import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse
from psycopg.rows import dict_row
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse

DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_EMAIL = os.environ["ADMIN_EMAIL"]
ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"]
UPLOAD_DIR = Path(os.environ.get("UPLOAD_DIR", "/app/uploads"))
MAX_UPLOAD_SIZE = 5 * 1024 * 1024
MAX_GALLERY_FILES = 10
ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp"}
LOGIN_WINDOW_SECONDS = 15 * 60
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}


def connect():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if len(JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET deve conter pelo menos 32 caracteres.")
    try:
        bcrypt.checkpw(b"configuration-check", ADMIN_PASSWORD_HASH.encode())
    except ValueError as error:
        raise RuntimeError("ADMIN_PASSWORD_HASH deve ser um hash bcrypt valido.") from error

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS "Memorial" (
                id BIGSERIAL PRIMARY KEY,
                nome TEXT NOT NULL,
                biografia TEXT,
                descricao TEXT,
                "dataNascimento" TEXT,
                "dataMorte" TEXT,
                localizacao TEXT,
                tipo TEXT DEFAULT 'historica',
                imagem TEXT,
                galeria TEXT[] NOT NULL DEFAULT '{}',
                "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
    yield


app = FastAPI(title="Memorial Digital API", version="1.0.0", lifespan=lifespan)


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(_: Request, error: StarletteHTTPException):
    detail = error.detail if isinstance(error.detail, str) else "Requisicao invalida."
    return JSONResponse(
        status_code=error.status_code,
        content={"erro": detail},
        headers=error.headers,
    )


def authenticate_admin(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token de autenticacao ausente.")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.InvalidTokenError as error:
        raise HTTPException(status_code=401, detail="Token invalido ou expirado.") from error

    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Acesso nao autorizado.")
    return payload


def row_to_dict(row):
    return {
        **row,
        "createdAt": row["createdAt"].isoformat(),
        "galeria": row["galeria"] or [],
    }


async def parse_payload(request: Request):
    if request.headers.get("content-type", "").startswith("multipart/form-data"):
        form = await request.form()
        return dict(form), form.getlist("galeria")
    try:
        payload = await request.json()
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Corpo JSON invalido.") from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="O corpo deve ser um objeto JSON.")
    return payload, []


async def save_image(upload: UploadFile):
    if not upload.filename:
        raise HTTPException(status_code=400, detail="Arquivo de imagem invalido.")
    extension = Path(upload.filename).suffix.lower()
    if extension not in ALLOWED_IMAGE_EXTENSIONS or not (upload.content_type or "").startswith("image/"):
        raise HTTPException(status_code=400, detail="Formato de imagem nao suportado.")

    contents = await upload.read(MAX_UPLOAD_SIZE + 1)
    if len(contents) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=413, detail="A imagem deve ter no maximo 5 MB.")

    filename = f"{uuid4().hex}{extension}"
    (UPLOAD_DIR / filename).write_bytes(contents)
    return f"/uploads/{filename}"


async def save_gallery(uploads):
    files = [upload for upload in uploads if isinstance(upload, UploadFile) and upload.filename]
    if len(files) > MAX_GALLERY_FILES:
        raise HTTPException(status_code=400, detail="A galeria aceita no maximo 10 imagens.")
    return [await save_image(upload) for upload in files]


def normalize_text(value, field, required=False):
    if value is None:
        if required:
            raise HTTPException(status_code=400, detail=f"O campo {field} e obrigatorio.")
        return None
    if not isinstance(value, str):
        raise HTTPException(status_code=400, detail=f"O campo {field} deve ser texto.")
    value = value.strip()
    if required and not value:
        raise HTTPException(status_code=400, detail=f"O campo {field} e obrigatorio.")
    return value or None


@app.get("/api/health")
def health_check():
    with connect() as connection:
        connection.execute("SELECT 1")
    return {"status": "ok", "database": "connected"}


@app.post("/api/login")
async def login(request: Request):
    try:
        credentials = await request.json()
    except ValueError as error:
        raise HTTPException(status_code=400, detail="Corpo JSON invalido.") from error

    email = credentials.get("email") if isinstance(credentials, dict) else None
    password = credentials.get("password") if isinstance(credentials, dict) else None
    client_ip = request.headers.get("x-real-ip") or (
        request.client.host if request.client else "unknown"
    )
    now = time.time()
    attempts = login_attempts.get(client_ip)
    if attempts and now - attempts["first_attempt"] >= LOGIN_WINDOW_SECONDS:
        login_attempts.pop(client_ip, None)
        attempts = None
    if attempts and attempts["count"] >= MAX_LOGIN_ATTEMPTS:
        retry_after = int(LOGIN_WINDOW_SECONDS - (now - attempts["first_attempt"]))
        raise HTTPException(
            status_code=429,
            detail="Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(max(1, retry_after))},
        )

    try:
        password_matches = (
            isinstance(password, str)
            and bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH.encode())
        )
    except ValueError:
        password_matches = False
    if email != ADMIN_EMAIL or not password_matches:
        login_attempts[client_ip] = {
            "count": (attempts["count"] if attempts else 0) + 1,
            "first_attempt": attempts["first_attempt"] if attempts else now,
        }
        raise HTTPException(status_code=401, detail="Credenciais invalidas.")

    login_attempts.pop(client_ip, None)
    token = jwt.encode(
        {
            "email": email,
            "role": "admin",
            "exp": datetime.now(timezone.utc) + timedelta(hours=8),
        },
        JWT_SECRET,
        algorithm="HS256",
    )
    return {"success": True, "token": token}


@app.get("/api/memoriais")
def list_memoriais():
    with connect() as connection:
        rows = connection.execute(
            'SELECT * FROM "Memorial" ORDER BY "createdAt" DESC'
        ).fetchall()
    return [row_to_dict(row) for row in rows]


@app.get("/api/memoriais/{memorial_id}")
def get_memorial(memorial_id: int):
    with connect() as connection:
        row = connection.execute(
            'SELECT * FROM "Memorial" WHERE id = %s', (memorial_id,)
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Memorial nao encontrado.")
    return row_to_dict(row)


@app.post("/api/memoriais", status_code=status.HTTP_201_CREATED)
async def create_memorial(
    request: Request,
    _: dict = Depends(authenticate_admin),
):
    payload, gallery_uploads = await parse_payload(request)
    gallery = await save_gallery(gallery_uploads)

    image_upload = payload.get("imagem")
    if isinstance(image_upload, UploadFile):
        image = await save_image(image_upload)
    else:
        image = normalize_text(image_upload, "imagem")
    if not image and gallery:
        image = gallery[0]

    name = normalize_text(payload.get("nome"), "nome", required=True)
    fields = {
        "biografia": normalize_text(payload.get("biografia"), "biografia"),
        "descricao": normalize_text(payload.get("descricao"), "descricao"),
        "dataNascimento": normalize_text(payload.get("dataNascimento"), "dataNascimento"),
        "dataMorte": normalize_text(payload.get("dataMorte"), "dataMorte"),
        "localizacao": normalize_text(payload.get("localizacao"), "localizacao"),
        "tipo": normalize_text(payload.get("tipo"), "tipo") or "historica",
        "imagem": image,
        "galeria": gallery,
    }

    with connect() as connection:
        row = connection.execute(
            """
            INSERT INTO "Memorial" (
                nome, biografia, descricao, "dataNascimento", "dataMorte",
                localizacao, tipo, imagem, galeria
            )
            VALUES (%(nome)s, %(biografia)s, %(descricao)s, %(dataNascimento)s,
                    %(dataMorte)s, %(localizacao)s, %(tipo)s, %(imagem)s, %(galeria)s)
            RETURNING *
            """,
            {"nome": name, **fields},
        ).fetchone()
    return row_to_dict(row)


@app.put("/api/memoriais/{memorial_id}")
async def update_memorial(
    memorial_id: int,
    request: Request,
    _: dict = Depends(authenticate_admin),
):
    payload, gallery_uploads = await parse_payload(request)
    with connect() as connection:
        existing = connection.execute(
            'SELECT * FROM "Memorial" WHERE id = %s', (memorial_id,)
        ).fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="Memorial nao encontrado.")

    gallery = await save_gallery(gallery_uploads) if gallery_uploads else existing["galeria"]
    image_upload = payload.get("imagem")
    if isinstance(image_upload, UploadFile):
        image = await save_image(image_upload)
    elif "imagem" in payload:
        image = normalize_text(image_upload, "imagem") or existing["imagem"]
    else:
        image = existing["imagem"]

    updates = {}
    for field in ("nome", "biografia", "descricao", "dataNascimento", "dataMorte", "localizacao", "tipo"):
        if field in payload:
            updates[field] = normalize_text(payload[field], field, required=field == "nome")
        else:
            updates[field] = existing[field]

    if not updates["nome"]:
        raise HTTPException(status_code=400, detail="O campo nome e obrigatorio.")

    if gallery and "imagem" not in payload and not image:
        image = gallery[0]
    values = {
        "id": memorial_id,
        **updates,
        "imagem": image,
        "galeria": gallery,
    }
    with connect() as connection:
        row = connection.execute(
            """
            UPDATE "Memorial"
            SET nome = %(nome)s, biografia = %(biografia)s, descricao = %(descricao)s,
                "dataNascimento" = %(dataNascimento)s, "dataMorte" = %(dataMorte)s,
                localizacao = %(localizacao)s, tipo = %(tipo)s, imagem = %(imagem)s,
                galeria = %(galeria)s
            WHERE id = %(id)s
            RETURNING *
            """,
            values,
        ).fetchone()
    return row_to_dict(row)


@app.delete("/api/memoriais/{memorial_id}")
def delete_memorial(
    memorial_id: int,
    _: dict = Depends(authenticate_admin),
):
    with connect() as connection:
        cursor = connection.execute(
            'DELETE FROM "Memorial" WHERE id = %s', (memorial_id,)
        )
    if cursor.rowcount == 0:
        raise HTTPException(status_code=404, detail="Memorial nao encontrado.")
    return {"mensagem": "Memorial removido com sucesso."}


@app.get("/uploads/{filename}")
def get_upload(filename: str):
    if not re.fullmatch(r"[a-f0-9]{32}\.(jpg|jpeg|png|gif|webp)", filename):
        raise HTTPException(status_code=404, detail="Arquivo nao encontrado.")
    file_path = UPLOAD_DIR / filename
    if not file_path.is_file():
        raise HTTPException(status_code=404, detail="Arquivo nao encontrado.")
    return FileResponse(file_path)
