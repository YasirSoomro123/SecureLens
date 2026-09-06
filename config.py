import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "arzens-sast-secret-key-2026")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"py", "js", "html", "php", "java", "ts", "jsx", "tsx", "rb", "go", "cs", "sql", "yml", "yaml", "json", "xml", "env", "cfg", "conf", "ini", "txt"}
    SCAN_EXTENSIONS = {"py", "js", "ts", "jsx", "tsx", "html", "java", "php", "rb", "go", "cs", "yml", "yaml", "json", "env", "cfg", "conf", "ini"}
    SUPPORTED_LANGUAGES = {
        "py": "Python",
        "js": "JavaScript",
        "ts": "TypeScript",
        "jsx": "JavaScript (JSX)",
        "tsx": "TypeScript (TSX)",
        "html": "HTML",
        "java": "Java",
        "php": "PHP",
        "rb": "Ruby",
        "go": "Go",
        "cs": "C#",
        "yml": "YAML",
        "yaml": "YAML",
        "json": "JSON",
        "env": "Environment Config",
        "cfg": "Config",
        "conf": "Config",
        "ini": "INI",
    }
