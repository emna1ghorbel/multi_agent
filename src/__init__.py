
from extract_entities import extract_entities
from rag_search import rag_search
from detect_patterns import detect_patterns
from detect_behaviors import detect_behaviors
from threat_brief import build_threat_brief

CTI_TOOLS = [
    extract_entities,   
    rag_search,        
    detect_patterns,   
    detect_behaviors,   
]
