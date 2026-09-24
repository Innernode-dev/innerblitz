from pathlib import Path
from typing import Optional, Dict, Any
from starlette.requests import Request
from fastapi.templating import Jinja2Templates

templates_dir = Path(__file__).parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))

def render_template(
    request: Request,
    name: str,
    context: Optional[Dict[str, Any]] = None,
    status_code: int = 200,
    headers: Optional[Dict[str, str]] = None
):
    """
    Render a Jinja2 template safely across all Starlette versions (including 0.35+ and 1.x).
    Always ensures 'request' is present in context and handles positional vs keyword changes.
    """
    ctx = dict(context) if context else {}
    ctx["request"] = request
    try:
        # Starlette 0.35+ and 1.x: TemplateResponse(request=request, name=name, context=context, ...)
        return templates.TemplateResponse(
            request=request,
            name=name,
            context=ctx,
            status_code=status_code,
            headers=headers
        )
    except TypeError:
        # Legacy Starlette: TemplateResponse(name, context, status_code=..., headers=...)
        return templates.TemplateResponse(
            name,
            ctx,
            status_code=status_code,
            headers=headers
        )
