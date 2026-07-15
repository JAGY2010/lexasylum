# LexAsylum v2.0 — Deploy en Railway

## Variables de entorno requeridas en Railway:
- `ANTHROPIC_API_KEY` 
- `DATABASE_URL` 
- `SESSION_SECRET` 
- `NODE_ENV` 

## Estructura del proyecto:
```
lexasylum/
├── server.js          # Backend con auth y DB
├── package.json
├── railway.json
└── public/
    └── index.html     # La app (renombrar app.html → public/index.html)
```

## Credenciales iniciales:
- Superadmin: 
## Deploy paso a paso:
1. Crear repo en GitHub y subir estos archivos
2. En Railway: New Project → Deploy from GitHub
3. Agregar servicio PostgreSQL en Railway
4. Configurar variables de entorno
5. Deploy automático
6. En Namecheap: apuntar DNS a Railway domain 
