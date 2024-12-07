from fastapi import FastAPI
import os
import psycopg2
from psycopg2.extras import RealDictCursor

app = FastAPI()

# Configuração da conexão com o banco de dados
DATABASE_URL = os.getenv("DATABASE_URL")

@app.get("/")
async def root():
    return {"message": "API funcionando!"}

@app.get("/db-status")
async def db_status():
    try:
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        conn.close()
        return {"status": "Banco de dados conectado com sucesso!"}
    except Exception as e:
        return {"status": "Erro ao conectar ao banco de dados", "error": str(e)}
