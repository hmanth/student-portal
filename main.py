
from dotenv import load_dotenv, dotenv_values
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from database import Base, engine, get_db
from model import User
from security import hash_password, verify_password

load_dotenv()

app = FastAPI()

secret_key = dotenv_values(".env").get("SESSION_SECRET")

if not secret_key:
    raise RuntimeError("SESSION_SECRET is missing")

app.add_middleware(
    SessionMiddleware,
    secret_key=secret_key,
    https_only=False
)

templates = Jinja2Templates(directory="templates")

Base.metadata.create_all(bind=engine)


@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.id == request.session.get("user_id")
    ).first()

    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"user": user}
    )


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": None}
    )


@app.post("/register")
def register(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    name = name.strip()
    email = email.strip().lower()

    if not name or not email or not password:
        error = "All fields are required."

    elif len(password) < 8:
        error = "Password must contain at least 8 characters."

    elif db.query(User).filter(User.email == email).first():
        error = "Email already exists."

    else:
        user = User(
            name=name,
            email=email,
            password_hash=hash_password(password),
            role="student"
        )

        db.add(user)
        db.commit()

        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="register.html",
        context={"error": error},
        status_code=400
    )


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None}
    )


@app.post("/login")
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(
        User.email == email.strip().lower()
    ).first()

    if user and verify_password(password, user.password_hash):
        request.session.clear()
        request.session["user_id"] = user.id

        return RedirectResponse("/dashboard", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": "Invalid email or password."},
        status_code=401
    )


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.id == request.session.get("user_id")
    ).first()

    if not user:
        return RedirectResponse("/login", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"user": user}
    )


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.id == request.session.get("user_id")
    ).first()

    if not user:
        return RedirectResponse("/login", status_code=303)

    if user.role != "admin":
        return templates.TemplateResponse(
            request=request,
            name="access_denied.html",
            context={},
            status_code=403
        )

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={"user": user}
    )


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
