# Usando Python como base
FROM python:3.11-slim

# Definir diretório de trabalho no container
WORKDIR /app

# Copiar arquivos de dependências
COPY requirements.txt .

# Instalar dependências do Python
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todo o código da aplicação
COPY . .

# Expor a porta 8000
EXPOSE 8000

# Comando para rodar o servidor
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
