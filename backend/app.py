from fastapi import FastAPI, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import pyotp
from passlib.hash import bcrypt
from dotenv import load_dotenv

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

# Modelo Pydantic
class User(BaseModel):
    email: EmailStr
    password: str

class OTPValidation(BaseModel):
    email: EmailStr
    otp: str

@app.post("/users/")
async def create_user(user: User):
    """Cria um novo usuário com segredo OTP."""
    try:
        # Gerar segredo OTP e hash de senha
        otp_secret = pyotp.random_base32()
        hashed_password = bcrypt.hash(user.password)

        # Inserir usuário no banco de dados
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

@app.get("/otp/{email}")
async def get_otp(email: str):
    """Gera um código OTP baseado no segredo do usuário."""
    try:
        # Logando a tentativa de buscar OTP
        print(f"Recebendo requisição para /otp/{email}")
        
        # Buscar segredo OTP do usuário
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT otp_secret FROM users WHERE email = %s", (email,))
                user = cursor.fetchone()
        
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")
        
        # Gerar código OTP
        totp = pyotp.TOTP(user["otp_secret"])
        otp_code = totp.now()

        return {"otp": otp_code, "expires_in": 30}  # Expires in 30 seconds
    except psycopg2.Error as e:
        print(f"Erro no banco de dados: {e}")
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e.pgerror}")
    except Exception as e:
        print(f"Erro desconhecido: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno no servidor: {e}")

@app.post("/auth/validate-otp/")
async def validate_otp(data: OTPValidation):
    """Valida o código OTP do usuário."""
    try:
        # Buscar segredo OTP do usuário
        with psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor) as conn:
            with conn.cursor() as cursor:
                cursor.execute("SELECT otp_secret FROM users WHERE email = %s", (data.email,))
                user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        # Validar código OTP
        totp = pyotp.TOTP(user["otp_secret"])
        if not totp.verify(data.otp):
            raise HTTPException(status_code=400, detail="Código OTP inválido ou expirado")

        return {"message": "Autenticação 2FA bem-sucedida!"}
    except psycopg2.Error as e:
        raise HTTPException(status_code=500, detail=f"Erro no banco de dados: {e.pgerror}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro interno no servidor: {e}")
