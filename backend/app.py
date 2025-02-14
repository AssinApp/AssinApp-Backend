from fastapi import FastAPI, HTTPException, Depends, File, UploadFile, Form
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
import hashlib
import base64
import jwt


from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


load_dotenv()

app = FastAPI()


origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000", 
    "http://192.168.1.10:3000",  
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

SECRET_KEY="4b9ce953b6a221989c9eed27d86c874b961fdebc9bfe38a8d68f4722ef84dbc7502b3cec84b6f4656fbcff04ed757e40d9eb8d75b66e0176b9b0e335af142731b0d42bd9327d9939fd76c34972339f1d1695899c8cc1ce633747132c4061a43eac24cfc6725f580a3d85d0c7d5f7206161fbedf6bd24da77d91808bb32f7d93898d86614abc4c916b0f6581dde61dd7f933e869c40574d10bc10d7726f6e7dcaf43a408c401a6202b6e215729f0f52ceeabe4f5f2e4db3b28c55d56ff2b899ee9a2b87015379ff633c776959e4bbd479a636d46e6854b62ee9c6a8acc8402f4f94ae8632324531f43f9a16063b12dc0f9136f0f3eea131e6210d72cc994f824c"
ALGORITHM ="HS256"
ACCESS_TOKEN_HOURS = 1

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def decode_jwt(token: str):
    """
    Decodifica e valida um JWT retornando o payload.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None

# Diretório de uploads
UPLOAD_DIRECTORY = "uploads"
os.makedirs(UPLOAD_DIRECTORY, exist_ok=True)  # Criar diretório caso não exista

def create_access_token(user_id: str, username: str, expires_delta: timedelta = None):
    to_encode = {
        "issuer": "webapp_test",
        "user_id": user_id,  
        "sub": username, 
        "exp": datetime.utcnow() + (expires_delta or timedelta(hours=ACCESS_TOKEN_HOURS)),
    }
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    print(f"[DEBUG] Token Gerado: {token}")  # <-- ADICIONE ISSO
    return token

class User(BaseModel):
    name: str
    email: EmailStr
    password: str
    public_key: str = None  
    
    
@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    """
    Rota protegida que retorna informações do usuário autenticado.
    """
    payload = decode_jwt(token)
    
    if not payload:
        raise HTTPException(status_code=401, detail="Token inválido")

    email = payload.get("sub")
    
    if not email:
        raise HTTPException(status_code=401, detail="Token inválido")

    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, name, email FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        return {"id": user["id"], "name": user["name"], "email": user["email"]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")


@app.post("/users/")
async def create_user(user: User):
    """
    Cria um usuário, salva o hash da senha e, opcionalmente,
    a chave pública (public_key).
    """
    try:
        print(f"[DEBUG] Recebendo cadastro de usuário: {user.email}")
        otp_secret = pyotp.random_base32()
        hashed_password = bcrypt.hash(user.password)

        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO users (name, email, password_hash, otp_secret, public_key_pem)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                    """,
                    (
                        user.name,
                        user.email,
                        hashed_password,
                        otp_secret,
                        user.public_key,  
                    ),
                )
                user_id = cursor.fetchone()["id"]
                conn.commit()

        print("[DEBUG] Novo usuário cadastrado com ID:", user_id)
        return {
            "id": user_id,
            "otp_secret": otp_secret,
            "message": "Usuário criado com sucesso!"
        }

    except psycopg2.Error as e:
        print("[ERROR] Erro no banco de dados:", e.pgerror)
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e.pgerror}")
    except Exception as e:
        print("[ERROR] Erro interno:", str(e))
        raise HTTPException(status_code=500, detail=f"Erro interno no servidor: {str(e)}")

@app.get("/otp/{email}")
async def get_otp(email: str):
    """
    Gera um código OTP baseado no segredo do usuário.
    """
    print(f"[DEBUG] Solicitando OTP para email: {email}")
    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT otp_secret FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

        if not user:
            print("[WARNING] Usuário não encontrado para OTP.")
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        totp = pyotp.TOTP(user["otp_secret"])
        otp_code = totp.now()

        print("[DEBUG] OTP gerado:", otp_code)
        return {"otp": otp_code, "expires_in": 30}

    except psycopg2.Error as e:
        print("[ERROR] Erro no banco de dados:", e.pgerror)
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e.pgerror}")
    except Exception as e:
        print("[ERROR] Erro interno:", str(e))
        raise HTTPException(status_code=500, detail=f"Erro interno no servidor: {str(e)}")

@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    print("[DEBUG] Tentando login para usuário:", form_data.username)
    try:
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, password_hash FROM users WHERE email = %s", (form_data.username,))
                user = cursor.fetchone()

        if not user:
            print("[WARNING] Usuário não encontrado.")
            raise HTTPException(status_code=401, detail="Credenciais inválidas")

        if not bcrypt.verify(form_data.password, user["password_hash"]):
            print("[WARNING] Senha incorreta.")
            raise HTTPException(status_code=401, detail="Credenciais inválidas")

        access_token = create_access_token(user_id=str(user["id"]), username=form_data.username)

        print("[DEBUG] Login bem-sucedido. Token gerado.")
        return {"access_token": access_token, "token_type": "bearer"}

    except Exception as e:
        print("[ERROR] Erro ao processar login:", str(e))
        raise HTTPException(status_code=500, detail=f"Erro ao processar login: {str(e)}")

@app.get("/users/me")
async def read_users_me(token: str = Depends(oauth2_scheme)):
    print("[DEBUG] /users/me requisitado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if not email:
            print("[WARNING] Token inválido, campo 'sub' ausente.")
            raise HTTPException(status_code=401, detail="Token inválido")

        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT name, email FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()

        if not user:
            print("[WARNING] Usuário não encontrado no banco.")
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        print("[DEBUG] Retornando dados do usuário:", user["name"], user["email"])
        return {"name": user["name"], "email": user["email"]}

    except JWTError:
        print("[WARNING] Token inválido (JWTError).")
        raise HTTPException(status_code=401, detail="Token inválido")
    except Exception as e:
        print("[ERROR] Erro interno em /users/me:", str(e))
        raise HTTPException(status_code=500, detail=f"Erro interno: {str(e)}")

@app.post("/upload/")
async def upload_pdf(file: UploadFile = File(...)):
    print("[DEBUG] Recebendo arquivo para upload:", file.filename)
    if file.content_type != "application/pdf":
        print("[WARNING] Tipo de arquivo não é PDF:", file.content_type)
        raise HTTPException(status_code=400, detail="Apenas arquivos PDF são permitidos.")

    file_path = Path(UPLOAD_DIRECTORY) / file.filename

    try:
        with open(file_path, "wb") as f:
            content = await file.read()
            f.write(content)
        print("[DEBUG] Arquivo salvo em:", file_path)
        return {"message": "Arquivo enviado com sucesso!", "file_url": f"/files/{file.filename}"}
    except Exception as e:
        print("[ERROR] Falha ao salvar arquivo:", str(e))
        raise HTTPException(status_code=500, detail="Falha ao salvar arquivo")

@app.get("/files/{filename}")
async def get_file(filename: str):
    file_path = Path(UPLOAD_DIRECTORY) / filename
    print("[DEBUG] Buscando arquivo:", file_path)
    if not file_path.exists():
        print("[WARNING] Arquivo não encontrado:", file_path)
        raise HTTPException(status_code=404, detail="Arquivo não encontrado.")

    return FileResponse(
        file_path,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"}
    )

@app.post("/verify-signature")
async def verify_signature(
    file: UploadFile = File(...),
    signature_b64: str = Form(...),
    token: str = Depends(oauth2_scheme)
):
    """
    Recebe um PDF e a assinatura (base64) do hash desse PDF, e verifica
    usando a chave pública do usuário identificado pelo token.
    """
    print("[DEBUG] /verify-signature chamado.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        if not user_email:
            print("[WARNING] Token inválido, sub não encontrado.")
            raise HTTPException(status_code=401, detail="Token inválido")

        print("[DEBUG] Usuário autenticado:", user_email)

        
        pdf_bytes = await file.read()
        print("[DEBUG] Tamanho do arquivo recebido:", len(pdf_bytes), "bytes.")

        # Gera hash SHA-256
        pdf_hash = hashlib.sha256(pdf_bytes).digest()
        print("[DEBUG] Hash gerado (SHA-256) do PDF:", pdf_hash.hex())

        # Recupera a chave pública do usuário
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT public_key_pem FROM users WHERE email = %s", (user_email,))
                row = cursor.fetchone()
                if not row:
                    print("[WARNING] Usuário não encontrado no DB ou sem chave pública.")
                    raise HTTPException(status_code=404, detail="Usuário não encontrado ou sem chave pública")
                public_key_pem = row["public_key_pem"]

        if not public_key_pem:
            print("[WARNING] Chave pública não cadastrada.")
            raise HTTPException(status_code=400, detail="Chave pública não cadastrada para este usuário.")

        # Carrega a chave pública (PEM)
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        except Exception as e:
            print("[ERROR] Falha ao carregar chave pública:", str(e))
            raise HTTPException(status_code=400, detail="Formato de chave pública inválido.")

        # Decodifica a assinatura base64
        try:
            signature = base64.b64decode(signature_b64)
        except Exception:
            print("[WARNING] Falha no base64 decode da assinatura.")
            raise HTTPException(status_code=400, detail="Assinatura inválida (base64 decode falhou)")

        # Verifica a assinatura
        try:
            public_key.verify(
                signature,
                pdf_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        except Exception as e:
            print("[WARNING] Assinatura inválida:", str(e))
            raise HTTPException(status_code=400, detail="Assinatura inválida (falha na verificação)")

        print("[DEBUG] Assinatura válida. Tudo certo.")
        return {"status": "success", "detail": "Assinatura verificada com sucesso!"}

    except JWTError:
        print("[WARNING] Falha no JWT decode.")
        raise HTTPException(status_code=401, detail="Token inválido")
    except Exception as e:
        print("[ERROR] Exceção em /verify-signature:", str(e))
        raise HTTPException(status_code=500, detail=str(e))
