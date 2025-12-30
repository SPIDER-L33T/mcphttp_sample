import os
import sys
import logging
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, List, Dict
from contextlib import asynccontextmanager
from functools import wraps

from fastapi import FastAPI, HTTPException, Depends, Request, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import jwt

# Настройка логирования для контейнера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]  # Только stdout для Docker
)
logger = logging.getLogger(__name__)

# Загрузка конфигурации из переменных окружения
from dotenv import load_dotenv
load_dotenv()

# Конфигурация безопасности
SECRET_KEY = os.getenv("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "100"))
cors_origins = os.getenv("ALLOWED_ORIGINS", "")
ALLOWED_ORIGINS = [origin.strip() for origin in cors_origins.split(",") if origin.strip()]
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "false").lower() == "true"

# Модели данных
class TextContent(BaseModel):
    type: str = "text"
    text: str

    @field_validator('text')
    @classmethod
    def sanitize_text(cls, v):
        """Санкционизация текста для предотвращения XSS"""
        import html
        # Экранируем HTML-символы
        return html.escape(v, quote=False)

class CallToolRequest(BaseModel):
    name: str
    arguments: Optional[dict] = None
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        """Валидация имени инструмента"""
        if not v.replace('_', '').isalnum():
            raise ValueError('Имя инструмента может содержать только буквы, цифры и подчеркивания')
        if len(v) > 100:
            raise ValueError('Имя инструмента слишком длинное')
        return v
    
    @field_validator('arguments')
    @classmethod
    def validate_arguments(cls, v):
        """Валидация аргументов"""
        if v is not None:
            # Проверка глубины JSON
            def check_depth(obj, depth=0, max_depth=10):
                if depth > max_depth:
                    raise ValueError('Превышена максимальная глубина JSON')
                if isinstance(obj, dict):
                    for value in obj.values():
                        check_depth(value, depth + 1, max_depth)
                elif isinstance(obj, list):
                    for item in obj:
                        check_depth(item, depth + 1, max_depth)
            
            check_depth(v)
            
            # Проверка размера
            if len(json.dumps(v)) > 10000:  # 10KB max
                raise ValueError('Слишком большой объем аргументов')
        return v

class Tool(BaseModel):
    name: str
    description: str
    inputSchema: dict = Field(alias="inputSchema")

class ListToolsResponse(BaseModel):
    tools: List[Tool]

# MCP JSON-RPC модели
class JSONRPCRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    method: str
    params: Optional[Dict[str, Any]] = None

class JSONRPCResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: Optional[Any] = None
    result: Optional[Any] = None
    error: Optional[Dict[str, Any]] = None
    
    def model_dump(self, **kwargs):
        """Переопределяем для исключения null полей и соблюдения JSON-RPC 2.0"""
        data = super().model_dump(exclude_none=True, **kwargs)
        # В JSON-RPC 2.0 не должно быть одновременно result и error
        if "error" in data and data["error"] is not None:
            data.pop("result", None)
        elif "result" in data and data["result"] is not None:
            data.pop("error", None)
        return data
    
    def dict(self, **kwargs):
        """Переопределяем для обратной совместимости"""
        return self.model_dump(**kwargs)

# Security
security_scheme = HTTPBearer(auto_error=False)

# In-memory хранилище для rate limiting (заменяет Redis)
from collections import defaultdict
from threading import Lock
import time

class MemoryRateLimiter:
    """In-memory rate limiter для использования без Redis"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = Lock()
    
    def is_allowed(self, key: str, limit: int, window: int = 60) -> bool:
        """Проверяет, разрешен ли запрос"""
        with self.lock:
            current_time = time.time()
            
            # Удаляем старые записи
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if current_time - req_time < window
            ]
            
            # Проверяем лимит
            if len(self.requests[key]) < limit:
                self.requests[key].append(current_time)
                return True
            
            return False
    
    def get_remaining(self, key: str, limit: int, window: int = 60) -> int:
        """Возвращает оставшееся количество запросов"""
        with self.lock:
            current_time = time.time()
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if current_time - req_time < window
            ]
            return max(0, limit - len(self.requests[key]))

rate_limiter = MemoryRateLimiter()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Контекст жизненного цикла приложения"""
    logger.info("MCP Time Server запущен")
    logger.info(f"Аутентификация: {'ВКЛ' if ENABLE_AUTH else 'ВЫКЛ'}")
    logger.info(f"Rate limit: {RATE_LIMIT_PER_MINUTE}/минуту")
    logger.info(f"Разрешенные origins: {ALLOWED_ORIGINS}")
    
    yield
    
    logger.info("MCP Time Server остановлен")

# Создание FastAPI приложения
app = FastAPI(
    title="MCP Time Server",
    description="Secure MCP сервер для работы с датой и временем",
    version="2.0.0",
    docs_url="/docs" if os.getenv("ENABLE_DOCS", "false").lower() == "true" else None,
    redoc_url=None,
    lifespan=lifespan
)

# Middleware
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
        expose_headers=["X-RateLimit-Limit", "X-RateLimit-Remaining"]
    )
    logger.info(f"CORS включен для origins: {ALLOWED_ORIGINS}")
else:
    logger.info("CORS отключен (ALLOWED_ORIGINS не указаны)")

allowed_hosts = ["localhost", "127.0.0.1"] + [h.strip() for h in os.getenv("ALLOWED_HOSTS", "").split(",") if h.strip()]
if allowed_hosts and allowed_hosts[0]:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts
    )

# Функции безопасности
def validate_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_scheme)
):
    """Валидация API ключа"""
    if not ENABLE_AUTH:
        return True
    
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не предоставлены учетные данные",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # В реальном приложении здесь была бы проверка ключа в БД
    expected_key = os.getenv("API_KEY")
    if not expected_key or credentials.credentials != expected_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный API ключ",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return True

async def rate_limit_check(request: Request):
    """Проверка rate limit с использованием memory storage"""
    client_ip = get_remote_address(request)
    
    if not rate_limiter.is_allowed(client_ip, RATE_LIMIT_PER_MINUTE):
        remaining = rate_limiter.get_remaining(client_ip, RATE_LIMIT_PER_MINUTE)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Превышен лимит запросов. Попробуйте позже.",
            headers={
                "X-RateLimit-Limit": str(RATE_LIMIT_PER_MINUTE),
                "X-RateLimit-Remaining": str(remaining),
                "X-RateLimit-Reset": str(int(time.time() + 60))  # Сброс через 60 секунд
            }
        )
    
    # Добавляем заголовки с информацией о лимитах
    remaining = rate_limiter.get_remaining(client_ip, RATE_LIMIT_PER_MINUTE)
    request.state.rate_limit_headers = {
        "X-RateLimit-Limit": str(RATE_LIMIT_PER_MINUTE),
        "X-RateLimit-Remaining": str(remaining)
    }
    
    return True

def audit_log(action: str, details: Dict, request: Request):
    """Логирование действий для аудита (только в stdout)"""
    client_ip = get_remote_address(request)
    logger.info(f"AUDIT: {action} - {details} - IP: {client_ip}")

# Обработчики ошибок
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Обработчик ошибок валидации"""
    logger.warning(f"Ошибка валидации: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Ошибка валидации запроса"},
    )

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Обработчик HTTP исключений"""
    headers = getattr(request.state, 'rate_limit_headers', {})
    if exc.status_code == 429:
        headers.update(exc.headers or {})
    
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=headers
    )

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Обработчик общих исключений"""
    logger.error(f"Неожиданная ошибка: {str(exc)}", exc_info=True)
    
    # В продакшене не раскрываем детали ошибок
    detail = "Внутренняя ошибка сервера"
    if os.getenv("ENV", "production") == "development":
        detail = f"{type(exc).__name__}: {str(exc)}"
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": detail},
    )

# Эндпоинты
@app.get("/tools", 
         response_model=ListToolsResponse,
         dependencies=[Depends(rate_limit_check)])
async def list_tools(
    request: Request,
    auth: bool = Depends(validate_api_key)
):
    """Возвращает список доступных инструментов"""
    audit_log("list_tools", {}, request)
    
    headers = getattr(request.state, 'rate_limit_headers', {})
    
    return JSONResponse(
        content=ListToolsResponse(
            tools=[
                Tool(
                    name="get_current_time",
                    description="Возвращает текущую дату и время в указанном формате",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "format": {
                                "type": "string",
                                "description": "Формат времени (например: 'iso', 'timestamp' или strftime)",
                                "default": "iso",
                                "maxLength": 100,
                                "pattern": "^[A-Za-z0-9%_:\\-/. ]+$"
                            }
                        },
                        "additionalProperties": False,
                        "maxProperties": 1
                    }
                )
            ]
        ).dict(),
        headers=headers
    )

@app.post("/tools/call")
async def call_tool(
    request: Request,
    call_request: CallToolRequest,
    auth: bool = Depends(validate_api_key)
):
    """Вызывает указанный инструмент с переданными аргументами"""
    # Проверка rate limit
    await rate_limit_check(request)
    
    audit_log("call_tool", {"tool": call_request.name}, request)
    
    # Валидация имени инструмента
    if call_request.name not in ["get_current_time"]:
        logger.warning(f"Попытка вызова неизвестного инструмента: {call_request.name}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Инструмент '{call_request.name}' не найден"
        )
    
    if call_request.name == "get_current_time":
        result = await handle_get_current_time(call_request.arguments or {}, request)
        headers = getattr(request.state, 'rate_limit_headers', {})
        return JSONResponse(content=result, headers=headers)
    
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Инструмент '{call_request.name}' не найден"
    )

async def handle_get_current_time(arguments: dict, request: Request) -> dict:
    """Обработчик для получения текущего времени с дополнительными проверками"""
    try:
        # Валидация аргументов
        if arguments:
            for key in arguments:
                if key != "format":
                    raise ValueError(f"Недопустимый параметр: {key}")
        
        if "format" in arguments:
            fmt = arguments["format"]
            # Проверка на опасные паттерны форматирования
            dangerous_patterns = ["%n", "%0", "%#", "%s", "%r", "%a"]
            if any(pattern in fmt for pattern in dangerous_patterns):
                raise ValueError("Недопустимый формат времени")
            
            # Ограничение длины
            if len(fmt) > 100:
                fmt = "iso"  # Fallback к безопасному формату
        
        # Получаем текущее время
        now = datetime.now(timezone.utc)
        
        # Обрабатываем формат
        fmt = arguments.get("format", "iso")
        
        if fmt == "iso":
            result = now.isoformat() + "Z"
        elif fmt == "timestamp":
            result = str(now.timestamp())
        elif fmt == "rfc3339":
            result = now.isoformat() + "Z"
        else:
            try:
                # Список разрешенных безопасных форматов
                safe_formats = [
                    "%Y-%m-%d", "%H:%M:%S", "%Y-%m-%d %H:%M:%S",
                    "%d.%m.%Y", "%d/%m/%Y", "%m/%d/%Y",
                    "%Y%m%d", "%H%M%S"
                ]
                
                # Проверяем, что формат содержит только разрешенные спецификаторы
                allowed_specifiers = ["%Y", "%m", "%d", "%H", "%M", "%S", "%y", "%%", " ", "-", ":", ".", "/"]
                temp_fmt = fmt
                for spec in allowed_specifiers:
                    temp_fmt = temp_fmt.replace(spec, "")
                
                # Если остались символы после удаления разрешенных - используем fallback
                if temp_fmt.strip():
                    result = now.isoformat() + "Z"
                else:
                    result = now.strftime(fmt)
            except Exception:
                # Безопасный fallback при ошибке
                result = now.isoformat() + "Z"
        
        logger.info(f"Инструмент get_current_time вызван успешно")
        
        # Возвращаем результат в формате MCP
        return {
            "content": [
                {
                    "type": "text",
                    "text": f"Текущее время (UTC): {result}"
                }
            ]
        }
        
    except ValueError as e:
        logger.warning(f"Ошибка валидации в get_current_time: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Ошибка в аргументах: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Ошибка в get_current_time: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Внутренняя ошибка при получении времени"
        )

# Эндпоинты для мониторинга
@app.get("/health")
async def health_check():
    """Проверка здоровья сервера"""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat() + "Z",
        "version": "2.0.0",
        "service": "mcp-time-server"
    }

@app.get("/")
async def root():
    """Корневой эндпоинт - возвращает информацию о сервере для MCP клиентов"""
    # Возвращаем информацию в формате, который может использовать Cursor
    return {
        "jsonrpc": "2.0",
        "result": {
            "serverInfo": {
                "name": "mcp-time-server",
                "version": "2.0.0"
            },
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            }
        },
        "service": "MCP Time Server",
        "version": "2.0.0",
        "documentation": "См. /docs если включены",
        "security": {
            "authentication_required": ENABLE_AUTH,
            "rate_limiting": f"{RATE_LIMIT_PER_MINUTE}/minute"
        }
    }

@app.post("/")
async def mcp_jsonrpc(
    request: Request,
    jsonrpc_request: JSONRPCRequest,
    auth: bool = Depends(validate_api_key)
):
    """Обработчик MCP JSON-RPC запросов на корневом пути"""
    # Проверка rate limit
    await rate_limit_check(request)
    
    audit_log("mcp_jsonrpc", {"method": jsonrpc_request.method}, request)
    
    headers = getattr(request.state, 'rate_limit_headers', {})
    
    try:
        # Обработка различных MCP методов
        result: Any = {}
        if jsonrpc_request.method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "mcp-time-server",
                    "version": "2.0.0"
                }
            }
        elif jsonrpc_request.method == "mcp/listOfferings":
            # Метод для получения информации о сервере (используется Cursor)
            result = {
                "serverInfo": {
                    "name": "mcp-time-server",
                    "version": "2.0.0"
                },
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {}
                }
            }
        elif jsonrpc_request.method == "tools/list":
            result = {
                "tools": [
                    {
                        "name": "get_current_time",
                        "description": "Возвращает текущую дату и время в указанном формате",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "format": {
                                    "type": "string",
                                    "description": "Формат времени (например: 'iso', 'timestamp' или strftime)",
                                    "default": "iso",
                                    "maxLength": 100,
                                    "pattern": "^[A-Za-z0-9%_:\\-/. ]+$"
                                }
                            },
                            "additionalProperties": False,
                            "maxProperties": 1
                        }
                    }
                ]
            }
        elif jsonrpc_request.method == "tools/call":
            if not jsonrpc_request.params:
                error_response = JSONRPCResponse(
                    id=jsonrpc_request.id,
                    error={
                        "code": -32602,
                        "message": "Параметры не предоставлены"
                    }
                )
                return JSONResponse(content=error_response.dict(), headers=headers)
            
            tool_name = jsonrpc_request.params.get("name")
            tool_args = jsonrpc_request.params.get("arguments", {})
            
            if not tool_name:
                error_response = JSONRPCResponse(
                    id=jsonrpc_request.id,
                    error={
                        "code": -32602,
                        "message": "Имя инструмента не указано"
                    }
                )
                return JSONResponse(content=error_response.dict(), headers=headers)
            
            if tool_name != "get_current_time":
                error_response = JSONRPCResponse(
                    id=jsonrpc_request.id,
                    error={
                        "code": -32601,
                        "message": f"Инструмент '{tool_name}' не найден"
                    }
                )
                return JSONResponse(content=error_response.dict(), headers=headers)
            
            # Вызываем обработчик инструмента
            try:
                tool_result = await handle_get_current_time(tool_args or {}, request)
                result = tool_result
            except HTTPException as e:
                error_response = JSONRPCResponse(
                    id=jsonrpc_request.id,
                    error={
                        "code": e.status_code,
                        "message": e.detail
                    }
                )
                return JSONResponse(content=error_response.dict(), headers=headers)
            except Exception as e:
                logger.error(f"Ошибка при вызове инструмента {tool_name}: {str(e)}", exc_info=True)
                error_response = JSONRPCResponse(
                    id=jsonrpc_request.id,
                    error={
                        "code": -32603,
                        "message": f"Ошибка при выполнении инструмента: {str(e)}"
                    }
                )
                return JSONResponse(content=error_response.dict(), headers=headers)
        else:
            # Неизвестный метод
            error_response = JSONRPCResponse(
                id=jsonrpc_request.id,
                error={
                    "code": -32601,
                    "message": f"Метод '{jsonrpc_request.method}' не найден"
                }
            )
            return JSONResponse(content=error_response.dict(), headers=headers)
        
        # Успешный ответ
        response = JSONRPCResponse(
            id=jsonrpc_request.id,
            result=result
        )
        return JSONResponse(content=response.dict(), headers=headers)
        
    except Exception as e:
        logger.error(f"Ошибка при обработке MCP запроса: {str(e)}", exc_info=True)
        error_response = JSONRPCResponse(
            id=jsonrpc_request.id if hasattr(jsonrpc_request, 'id') else None,
            error={
                "code": -32603,
                "message": "Внутренняя ошибка сервера"
            }
        )
        return JSONResponse(content=error_response.dict(), headers=headers, status_code=500)

if __name__ == "__main__":
    import uvicorn
    
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    
    # Конфигурация для продакшена
    reload = os.getenv("ENV", "production") == "development"
    log_level = "info" if os.getenv("ENV", "production") == "production" else "debug"
    
    logger.info(f"Запуск сервера на {host}:{port}")
    logger.info(f"Режим: {'development' if reload else 'production'}")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload,
        log_level=log_level,
        access_log=True,
        # Для HTTPS в продакшене:
        # ssl_keyfile=os.getenv("SSL_KEY_PATH"),
        # ssl_certfile=os.getenv("SSL_CERT_PATH")
    )
