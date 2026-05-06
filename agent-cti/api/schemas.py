from pydantic import BaseModel

class AnalyzeRequest(BaseModel):
    messages: list[str]
    rag_mode: bool = True
    web_search: bool = False
    notify: bool = False

class RagSearchRequest(BaseModel):
    query: str
    k: int = 5
