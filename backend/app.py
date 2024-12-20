from fastapi import FastAPI, HTTPException, Depends, File, UploadFile
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from jose import JWTError, jwt
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from dotenv import load_dotenv
from datetime import datetime, timedelta
import os
from pathlib import Path
import psycopg2
from psycopg2.extras import RealDictCursor
import pyotp

# Carregar variáveis de ambiente
load_dotenv()

app = FastAPI()

# Configurar CORS para permitir acesso do frontend
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",  # Outros locais para testes
    "http://192.168.1.10:3000",  # IP local
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuração do banco de dados
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL não configurado. Verifique suas variáveis de ambiente.")

SECRET_KEY = os.getenv("SECRET_KEY", "secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Diretório de uploads
UPLOAD_DIRECTORY = "uploads"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)  # Criar diretório caso não exista

# Função para criar token de acesso
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Modelo Pydantic
class User(BaseModel):
    email: EmailStr
    password: str

# Rota para criar usuário
@app.post("/users/")
async def create_user(user: User):
    try:
        otp_secret = pyotp.random_base32()
        hashed_password = bcrypt.hash(user.password)

        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (email, password_hash, otp_secret)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (user.email, hashed_password, otp_secret),
                )
                user_id = cursor.fetchone()["id"]
                conn.commit()

        return {"id": user_id, "otp_secret": otp_secret, "message": "Usuário criado com sucesso!"}
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e.pgerror}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro interno no servidor: {e}")

# Rota para login e geração de token
@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT password_hash FROM users WHERE email = %s", (form_data.username,))
                user = cursor.fetchone()
        if not user or not bcrypt.verify(form_data.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Credenciais inválidas")
        access_token = create_access_token(data={"sub": form_data.username})
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao processar login: {str(e)}")

# Rota para obter informações do usuário logado
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token inválido")
        return {"email": email}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

# Rota para upload de arquivos PDF
@app.post("/upload/")
async def upload_pdf(file: UploadFile = File(...)):
    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Apenas arquivos PDF são permitidos.")
    
    file_path = Path(UPLOAD_DIRECTORY) / file.filename

    with open(file_path, "wb") as f:
        content = await file.read()
        f.write(content)

    return {"message": "Arquivo enviado com sucesso!", "file_url": f"/files/{file.filename}"}

# Rota para servir arquivos PDF
@app.get("/files/{filename}")
async def get_file(filename: str):
    file_path = Path(UPLOAD_DIRECTORY) / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")

    return FileResponse(
        file_path,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"}
    )
