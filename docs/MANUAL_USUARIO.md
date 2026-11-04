# Manual de ejecución

## Preparación (solo la primera vez)

Abre PowerShell en la carpeta del proyecto.

**Backend:**

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

**Frontend**, en otra terminal desde la carpeta del proyecto:

```powershell
cd frontend
npm install
```

## Iniciar la aplicación

Abre dos terminales de PowerShell en la carpeta del proyecto.

**Terminal 1 — API:**

```powershell
cd backend

# Configura Gemini para habilitar las funciones de IA
$secureKey = Read-Host "API key de Gemini" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureKey)
try {
  $env:GEMINI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
}
finally {
  [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
}
$secureKey.Dispose()
$env:GEMINI_MODEL = "gemini-3.6-flash"

# Inicia la API
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

**Terminal 2 — interfaz:**

```powershell
cd frontend
npm run dev
```

Abre en el navegador la dirección que indique Vite; normalmente es `http://127.0.0.1:5173`.

Si omites la configuración de Gemini, ejecuta igualmente la línea de Uvicorn: la aplicación funcionará con análisis determinista, pero la IA quedará deshabilitada. Cada persona debe usar su propia API key. Como las variables solo duran en esa sesión de PowerShell, vuelve a introducirlas cada vez que inicies el backend para usar Gemini.

Para cerrar cada parte, pulsa `Ctrl+C` en su terminal.
