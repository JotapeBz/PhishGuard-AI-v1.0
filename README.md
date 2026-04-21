# 🛡️ PhishGuard AI

Motor de detección de phishing en tiempo real usando Machine Learning,
análisis SSL y extracción de features de URL.

## Demo
> API en producción: https://phishguard-ai.up.railway.app/docs

## Stack
- **Backend**: Python 3.11 · FastAPI · scikit-learn · XGBoost
- **Frontend**: React · Vite
- **Extension**: Chrome Extension Manifest V3
- **Deploy**: Docker · Railway

## Features del modelo (24 features)
- Entropía de Shannon del dominio
- Detección de IP disfrazada como dominio
- Análisis de TLDs sospechosos
- Presencia de marcas conocidas en subdominios
- Análisis de certificado SSL (emisor, edad, validez)
- Ratio de caracteres especiales y dígitos
- Y más...

## Resultados del modelo
| Métrica   | Valor  |
|-----------|--------|
| Accuracy  | ~96.5% |
| ROC-AUC   | ~99.2% |
| Precision | ~96%   |
| Recall    | ~97%   |

## Instalación local
```bash
git clone https://github.com/TU_USUARIO/phishguard-ai
cd phishguard-ai
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app/ml/train.py        # entrenar modelo
uvicorn app.main:app --reload # iniciar API
```

## Extensión Chrome
Cargar la carpeta `/extension` en `chrome://extensions` modo desarrollador.
