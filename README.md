# Workshop Requirements API — Python FastAPI

> **Laboratorio intencionalmente vulnerable.** Ejecutar únicamente en local, repositorios privados y ambientes aislados. No publicar en Internet ni desplegar en CERT/PROD.

API FastAPI que administra tareas del workshop y recibe archivos de requerimientos. Usa SQLite y consume el token emitido por el backend Quarkus.

## Ejecución

Requisitos: Python 3.13.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Swagger: `http://localhost:8000/docs`

Configura `AUTH_JWT_PUBLIC_KEY_PATH` con la ruta a la clave pública RSA PEM correspondiente a la clave privada del backend de autenticación. `AUTH_JWT_ISSUER` y `AUTH_JWT_AUDIENCE` son opcionales; sus valores predeterminados son `workshop-auth` y `workshop-requirements-api`. Mantén las claves fuera del repositorio.

## Endpoints

- `GET /api/tasks`
- `POST /api/tasks`
- `GET /api/summary`
- `POST /api/requirements`
- `GET /api/backend-health`

La API valida tokens JWT RS256 con firma, issuer, audience y expiración. Conserva deuda técnica fuera de este cambio, como SQL concatenado, manejo inseguro de nombres de archivo, conexión global, lógica monolítica y dependencias pendientes de revisión.
