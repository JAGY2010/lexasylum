# LexAsylum v2.0 — Deploy en Railway

## Variables de entorno requeridas en Railway:
- `ANTHROPIC_API_KEY` — tu clave de Anthropic
- `DATABASE_URL` — se configura automáticamente al agregar PostgreSQL
- `SESSION_SECRET` — string aleatorio largo (ej: genera uno en random.org)
- `NODE_ENV` — production

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
- Superadmin: juliangaviria29@gmail.com / Julian1994 (CAMBIAR AL ENTRAR)
- Hernando Bernal Jr — Marlon Pasaje: marlon@hbernallaw.com / Marlon2025! (CAMBIAR AL ENTRAR)

## Deploy paso a paso:
1. Crear repo en GitHub y subir estos archivos
2. En Railway: New Project → Deploy from GitHub
3. Agregar servicio PostgreSQL en Railway
4. Configurar variables de entorno
5. Deploy automático
6. En Namecheap: apuntar DNS a Railway domain
