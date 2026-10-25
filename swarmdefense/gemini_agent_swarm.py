from typing import Tuple

from .config import GEMINI_MODEL
from .gemini_client import get_client


class GeminiAgentSwarm:
    def call_gemini(self, role_instruction: str, prompt: str) -> Tuple[str, bool]:
        client = get_client()
        if client is None:
            return "GEMINI_API_KEY not configured.", False
        try:
            from google.genai import types

            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=role_instruction,
                    temperature=0.3,
                ),
            )
            return (response.text or "").strip(), True
        except Exception as e:
            return f"Gemini call failed: {e}", False
