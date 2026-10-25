import os

try:
    from google import genai
except ImportError:
    genai = None

_client = None


def get_client():
    global _client
    if _client is None:
        api_key = os.environ.get("GEMINI_API_KEY", "")
        if not api_key or genai is None:
            return None
        try:
            _client = genai.Client(api_key=api_key)
        except Exception:
            return None
    return _client


def set_api_key(api_key: str):
    global _client
    os.environ["GEMINI_API_KEY"] = api_key
    if genai is not None and api_key:
        try:
            _client = genai.Client(api_key=api_key)
            return True
        except Exception:
            _client = None
            return False
    else:
        _client = None
        return False
