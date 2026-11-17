mod auth;
mod store;

use std::{
    collections::HashMap,
    fs,
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Form, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path as UrlPath, State},
    http::{HeaderMap, HeaderValue, Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use clap::{Parser, Subcommand};
use qrcode::{QrCode, render::svg};
use rusqlite::Connection;
use serde::Deserialize;
use store::{
    NewShare, create_share, extend_share, list_shares, open_db, random_bytes, redeem, revoke_share,
};

#[derive(Parser)]
#[command(about = "Закрытая выдача VLESS профилей")]
struct Cli {
    #[arg(long, env = "PANEL_DATA_DIR", default_value = "data")]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Создать базу и секреты; пароль администратора читает из stdin
    Init,
    /// Запустить веб-панель (только loopback)
    Serve {
        #[arg(long, default_value = "127.0.0.1:3000")]
        bind: SocketAddr,
        #[arg(long, env = "PANEL_PUBLIC_URL")]
        public_url: String,
    },
    /// Выпустить ссылку для уже существующего VLESS URI из stdin
    Issue {
        #[arg(long)]
        person: String,
        #[arg(long)]
        device: String,
        #[arg(long, default_value_t = 30)]
        days: i64,
        #[arg(long)]
        max_views: Option<i64>,
        #[arg(long, env = "PANEL_PUBLIC_URL")]
        public_url: String,
    },
    /// Отозвать ссылку по номеру из списка
    Revoke { id: i64 },
    /// Продлить ссылку на заданное число дней от текущего момента
    Extend {
        id: i64,
        #[arg(long)]
        days: i64,
    },
    /// Показать записи без секретов
    List,
}

struct Session {
    csrf: String,
    expires: Instant,
}

struct AppState {
    db: Mutex<Connection>,
    key: [u8; 32],
    admin_hash: String,
    totp_secret: Vec<u8>,
    public_url: String,
    sessions: Mutex<HashMap<String, Session>>,
    login_attempts: Mutex<Vec<Instant>>,
    access_attempts: Mutex<Vec<Instant>>,
}

fn checked_url(raw: &str) -> Result<String, String> {
    let url = url::Url::parse(raw).map_err(|_| "Некорректный PANEL_PUBLIC_URL")?;
    if (url.scheme() != "https"
        && !(url.scheme() == "http"
            && url
                .host_str()
                .is_some_and(|host| host == "localhost" || host == "127.0.0.1")))
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err("PANEL_PUBLIC_URL должен быть HTTPS origin без пути (HTTP допустим только для localhost)".into());
    }
    Ok(url.origin().ascii_serialization())
}

fn read_fixed<const N: usize>(path: &Path) -> Result<[u8; N], String> {
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    bytes
        .try_into()
        .map_err(|_| format!("Неверная длина файла {}", path.display()))
}

fn check_private(path: &Path) -> Result<(), String> {
    let mode = fs::metadata(path)
        .map_err(|e| e.to_string())?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(format!("Слишком широкие права на {}", path.display()));
    }
    Ok(())
}

fn load_state(dir: &Path, public_url: String) -> Result<AppState, String> {
    for name in ["key", "admin.hash", "totp.secret", "shares.sqlite3"] {
        check_private(&dir.join(name))?;
    }
    let key = read_fixed::<32>(&dir.join("key"))?;
    let totp_secret = fs::read(dir.join("totp.secret")).map_err(|e| e.to_string())?;
    if totp_secret.len() != 20 {
        return Err("Неверный TOTP секрет".into());
    }
    let admin_hash = fs::read_to_string(dir.join("admin.hash")).map_err(|e| e.to_string())?;
    let db = open_db(&dir.join("shares.sqlite3")).map_err(|e| e.to_string())?;
    Ok(AppState {
        db: Mutex::new(db),
        key,
        admin_hash,
        totp_secret,
        public_url,
        sessions: Mutex::new(HashMap::new()),
        login_attempts: Mutex::new(Vec::new()),
        access_attempts: Mutex::new(Vec::new()),
    })
}

fn init(dir: &Path) -> Result<(), String> {
    if dir.exists()
        && fs::read_dir(dir)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("Каталог данных не пуст; инициализация отменена".into());
    }
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    eprintln!("Введите новый пароль администратора (минимум 16 символов) и нажмите Enter:");
    let mut password = String::new();
    io::stdin()
        .read_line(&mut password)
        .map_err(|e| e.to_string())?;
    let password = password.trim_end_matches(['\r', '\n']);
    if password.chars().count() < 16 {
        return Err("Пароль слишком короткий".into());
    }
    let hash = store::hash_password(password)?;
    let key = random_bytes::<32>();
    let totp = random_bytes::<20>();
    store::write_secret(&dir.join("key"), &key).map_err(|e| e.to_string())?;
    store::write_secret(&dir.join("admin.hash"), hash.as_bytes()).map_err(|e| e.to_string())?;
    store::write_secret(&dir.join("totp.secret"), &totp).map_err(|e| e.to_string())?;
    open_db(&dir.join("shares.sqlite3")).map_err(|e| e.to_string())?;
    fs::set_permissions(
        dir.join("shares.sqlite3"),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|e| e.to_string())?;
    println!(
        "Добавьте в приложение-аутентификатор TOTP (6 цифр, 30 секунд) секрет: {}",
        auth::provisioning_secret(&totp)
    );
    println!("Сохраните каталог данных и отдельно ключ шифрования в защищённой резервной копии.");
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Ошибка: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init => init(&cli.data_dir),
        Command::Serve { bind, public_url } => {
            if !matches!(bind.ip(), IpAddr::V4(ip) if ip.is_loopback())
                && !matches!(bind.ip(), IpAddr::V6(ip) if ip.is_loopback())
            {
                return Err(
                    "Панель может слушать только loopback; используйте HTTPS reverse proxy".into(),
                );
            }
            let state = Arc::new(load_state(&cli.data_dir, checked_url(&public_url)?)?);
            let app = router(state);
            let listener = tokio::net::TcpListener::bind(bind)
                .await
                .map_err(|e| e.to_string())?;
            println!(
                "Панель слушает {}",
                listener.local_addr().map_err(|e| e.to_string())?
            );
            axum::serve(listener, app).await.map_err(|e| e.to_string())
        }
        Command::Issue {
            person,
            device,
            days,
            max_views,
            public_url,
        } => {
            let state = load_state(&cli.data_dir, checked_url(&public_url)?)?;
            let mut uri = String::new();
            io::stdin()
                .read_to_string(&mut uri)
                .map_err(|e| e.to_string())?;
            let db = state.db.lock().unwrap();
            let created = create_share(
                &db,
                &state.key,
                &state.public_url,
                NewShare {
                    person: &person,
                    device: &device,
                    uri: uri.trim(),
                    days,
                    max_views,
                },
            )?;
            println!(
                "ID: {}\nСсылка: {}\nПароль: {}",
                created.id, created.link, created.password
            );
            Ok(())
        }
        Command::Revoke { id } => {
            let state = load_state(&cli.data_dir, "https://localhost".into())?;
            if !revoke_share(&state.db.lock().unwrap(), id).map_err(|e| e.to_string())? {
                return Err("Активная ссылка не найдена".into());
            }
            println!("Ссылка отозвана. UUID в Xray нужно отключить отдельно.");
            Ok(())
        }
        Command::Extend { id, days } => {
            let state = load_state(&cli.data_dir, "https://localhost".into())?;
            if !extend_share(&state.db.lock().unwrap(), id, days).map_err(|e| e.to_string())? {
                return Err("Активная ссылка не найдена или срок некорректен".into());
            }
            println!("Срок обновлён.");
            Ok(())
        }
        Command::List => {
            let state = load_state(&cli.data_dir, "https://localhost".into())?;
            for share in list_shares(&state.db.lock().unwrap()).map_err(|e| e.to_string())? {
                println!(
                    "{}\t{}\t{}\t{}\t{}/{}\t{}",
                    share.id,
                    share.person,
                    share.device,
                    share.expires_at,
                    share.views,
                    share.max_views.map_or("∞".into(), |n| n.to_string()),
                    if share.revoked {
                        "отозвана"
                    } else {
                        "активна"
                    }
                );
            }
            Ok(())
        }
    }
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(home))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .route("/admin/issue", post(issue))
        .route("/admin/revoke/{id}", post(revoke))
        .route("/admin/extend/{id}", post(extend))
        .route("/s/{token}", get(share_form).post(share_open))
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route(
            "/assets/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("style.css"),
                )
            }),
        )
        .route(
            "/assets/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("app.js"),
                )
            }),
        )
        .layer(DefaultBodyLimit::max(8192))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"));
    response
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page(title: &str, content: &str) -> Html<String> {
    Html(format!(
        "<!doctype html><html lang=ru><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><title>{}</title><link rel=stylesheet href=/assets/style.css></head><body><main><header><div class=brand>VLESS / sharing</div><h1>{}</h1></header>{}</main><script src=/assets/app.js defer></script></body></html>",
        esc(title),
        esc(title),
        content
    ))
}

fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| part.trim().strip_prefix("panel_session="))
}

fn session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = cookie(headers)?;
    let mut sessions = state.sessions.lock().ok()?;
    sessions.retain(|_, session| session.expires > Instant::now());
    sessions.get(token).map(|session| session.csrf.clone())
}

fn same_origin(state: &AppState, headers: &HeaderMap) -> bool {
    headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) == Some(state.public_url.as_str())
}

fn allow_attempt(attempts: &Mutex<Vec<Instant>>, limit: usize) -> bool {
    let mut attempts = attempts.lock().unwrap();
    attempts.retain(|time| time.elapsed() < Duration::from_secs(60));
    if attempts.len() >= limit {
        false
    } else {
        attempts.push(Instant::now());
        true
    }
}

async fn home(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let Some(csrf) = session(&state, &headers) else {
        return page("Вход владельца", "<section class=card><p>Закрытая панель выдачи VLESS-профилей.</p><form method=post action=/login><label>Пароль<input name=password type=password autocomplete=current-password required></label><label>Код аутентификатора<input name=code inputmode=numeric pattern='[0-9]{6}' maxlength=6 required></label><button>Войти</button></form></section>").into_response();
    };
    let shares = match list_shares(&state.db.lock().unwrap()) {
        Ok(v) => v,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut rows = String::new();
    for share in shares {
        let status = if share.revoked {
            "Отозвана"
        } else if chrono::DateTime::parse_from_rfc3339(&share.expires_at)
            .is_ok_and(|date| date <= chrono::Utc::now())
        {
            "Истекла"
        } else if share.max_views.is_some_and(|max| share.views >= max) {
            "Лимит исчерпан"
        } else {
            "Действует"
        };
        let actions = if share.revoked {
            String::new()
        } else {
            format!(
                "<form method=post action='/admin/extend/{}'><input type=hidden name=csrf value='{}'><input type=number name=days value=30 min=1 max=365 aria-label='Продлить на дней'><button class=secondary>Продлить</button></form><form method=post action='/admin/revoke/{}' data-confirm='Отозвать ссылку? Это не отключит UUID в Xray.'><input type=hidden name=csrf value='{}'><button class=danger>Отозвать ссылку</button></form>",
                share.id,
                esc(&csrf),
                share.id,
                esc(&csrf)
            )
        };
        rows.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td><span class=badge>{}</span></td><td class=actions>{}</td></tr>", share.id, esc(&share.person), esc(&share.device), esc(&share.expires_at[..10]), share.views, share.max_views.map_or("∞".into(), |n| n.to_string()), status, actions));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=7>Профилей пока нет.</td></tr>");
    }
    let content = format!(
        "<div class=topline><p>Создавайте отдельную ссылку для каждого человека и устройства.</p><form method=post action=/logout><input type=hidden name=csrf value='{}'><button class=secondary>Выйти</button></form></div><section class=card><h2>Новая ссылка</h2><p class=hint>Сначала создайте отдельный UUID на VPS РФ действующим скриптом и вставьте выданный клиентский URI. Панель хранит его в зашифрованном виде.</p><form method=post action=/admin/issue><input type=hidden name=csrf value='{}'><div class=grid><label>Человек<input name=person maxlength=80 required placeholder='Иван'></label><label>Устройство<input name=device maxlength=80 required placeholder='iPhone'></label><label>Срок, дней<input name=days type=number min=1 max=365 value=30 required></label><label>Лимит открытий (необязательно)<input name=max_views type=number min=1 max=1000></label></div><label>VLESS URI<textarea name=uri rows=4 maxlength=4096 required placeholder='vless://…'></textarea></label><button>Создать ссылку</button></form></section><section class=card><h2>Выданные профили</h2><div class=tablewrap><table><thead><tr><th>ID</th><th>Человек</th><th>Устройство</th><th>До</th><th>Открытий</th><th>Ссылка</th><th>Действия</th></tr></thead><tbody>{}</tbody></table></div><p class=hint>Отзыв ссылки закрывает страницу выдачи. Чтобы отключить уже импортированный профиль, отдельно удалите UUID клиента из Xray на VPS РФ.</p></section>",
        esc(&csrf),
        esc(&csrf),
        rows
    );
    page("Панель выдачи", &content).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    password: String,
    code: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    if !same_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !allow_attempt(&state.login_attempts, 10) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if !store::verify_password(&state.admin_hash, &form.password)
        || !auth::verify_totp(&state.totp_secret, &form.code)
    {
        return (StatusCode::UNAUTHORIZED, page("Вход не выполнен", "<section class=card><p>Неверные учётные данные.</p><a href=/>Повторить</a></section>")).into_response();
    }
    let token = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
    let csrf = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
    state.sessions.lock().unwrap().insert(
        token.clone(),
        Session {
            csrf,
            expires: Instant::now() + Duration::from_secs(20 * 60),
        },
    );
    let secure = if state.public_url.starts_with("https://") {
        "; Secure"
    } else {
        ""
    };
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("panel_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1200{secure}")
            .parse()
            .unwrap(),
    );
    response
}

#[derive(Deserialize)]
struct CsrfForm {
    csrf: String,
}

fn authorized(state: &AppState, headers: &HeaderMap, csrf: &str) -> bool {
    same_origin(state, headers) && session(state, headers).is_some_and(|expected| expected == csrf)
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !authorized(&state, &headers, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if let Some(token) = cookie(&headers) {
        state.sessions.lock().unwrap().remove(token);
    }
    let mut response = Redirect::to("/").into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        "panel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
            .parse()
            .unwrap(),
    );
    response
}

#[derive(Deserialize)]
struct IssueForm {
    csrf: String,
    person: String,
    device: String,
    uri: String,
    days: i64,
    #[serde(default)]
    max_views: String,
}

async fn issue(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<IssueForm>,
) -> Response {
    if !authorized(&state, &headers, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let max_views = if form.max_views.trim().is_empty() {
        None
    } else {
        match form.max_views.parse::<i64>() {
            Ok(value) => Some(value),
            Err(_) => return (StatusCode::BAD_REQUEST, page("Ссылка не создана", "<section class=card><p>Недопустимый лимит открытий.</p><a href=/>Вернуться</a></section>")).into_response(),
        }
    };
    let created = create_share(
        &state.db.lock().unwrap(),
        &state.key,
        &state.public_url,
        NewShare {
            person: &form.person,
            device: &form.device,
            uri: form.uri.trim(),
            days: form.days,
            max_views,
        },
    );
    match created {
        Ok(created) => page("Ссылка создана", &format!("<section class=card><p>Ссылка и пароль показаны только сейчас. Сохраните их и передайте получателю разными каналами.</p><label>Ссылка<input id=link readonly value='{}'></label><button class=secondary data-copy=link>Скопировать ссылку</button><label>Пароль<input id=share-password readonly value='{}'></label><button class=secondary data-copy=share-password>Скопировать пароль</button><p><a href=/>К списку профилей</a></p></section>", esc(&created.link), esc(&created.password))).into_response(),
        Err(error) => (StatusCode::BAD_REQUEST, page("Ссылка не создана", &format!("<section class=card><p>{}</p><a href=/>Вернуться</a></section>", esc(&error)))).into_response(),
    }
}

async fn revoke(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<i64>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    if !authorized(&state, &headers, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match revoke_share(&state.db.lock().unwrap(), id) {
        Ok(true) => Redirect::to("/").into_response(),
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
struct ExtendForm {
    csrf: String,
    days: i64,
}

async fn extend(
    State(state): State<Arc<AppState>>,
    UrlPath(id): UrlPath<i64>,
    headers: HeaderMap,
    Form(form): Form<ExtendForm>,
) -> Response {
    if !authorized(&state, &headers, &form.csrf) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match extend_share(&state.db.lock().unwrap(), id, form.days) {
        Ok(true) => Redirect::to("/").into_response(),
        Ok(false) => StatusCode::BAD_REQUEST.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn share_form(UrlPath(token): UrlPath<String>) -> Response {
    if token.len() != 43
        || !token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    page("Получить профиль", &format!("<section class=card><p>Введите пароль, который владелец передал вам отдельно.</p><form method=post action='/s/{}'><label>Пароль<input name=password type=password autocomplete=off required></label><button>Показать профиль</button></form></section>", esc(&token))).into_response()
}

#[derive(Deserialize)]
struct OpenForm {
    password: String,
}

async fn share_open(
    State(state): State<Arc<AppState>>,
    UrlPath(token): UrlPath<String>,
    headers: HeaderMap,
    Form(form): Form<OpenForm>,
) -> Response {
    if !same_origin(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if !allow_attempt(&state.access_attempts, 30) {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let uri = redeem(
        &mut state.db.lock().unwrap(),
        &state.key,
        &token,
        &form.password,
    );
    let Some(uri) = uri else {
        return (StatusCode::FORBIDDEN, page("Профиль недоступен", "<section class=card><p>Ссылка или пароль недействительны, либо срок или лимит доступа истёк.</p></section>")).into_response();
    };
    let code = match QrCode::new(uri.as_bytes()) {
        Ok(code) => code,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let svg = code.render::<svg::Color>().min_dimensions(220, 220).build();
    let image = STANDARD.encode(svg.as_bytes());
    page("Ваш VLESS-профиль", &format!("<section class=card><p>Скопируйте ссылку или отсканируйте QR в VLESS/REALITY-клиенте.</p><img class=qr alt='QR-код VLESS' src='data:image/svg+xml;base64,{}'><label>Профиль<textarea id=uri readonly rows=5>{}</textarea></label><button data-copy=uri>Скопировать профиль</button><p class=hint>Российские адреса выходят через VPS РФ, зарубежные — через VPS Нидерландов.</p></section>{}", image, esc(&uri), include_str!("client-routing.html"))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ORIGIN: &str = "https://panel.example";
    const URI: &str = "vless://c1013308-9b32-48fa-bf64-22a5b69bf972@example.org:443?security=reality&type=tcp#friend";

    fn test_state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir.path().join("shares.sqlite3")).unwrap();
        let state = AppState {
            db: Mutex::new(db),
            key: [7; 32],
            admin_hash: store::hash_password("correct-long-password").unwrap(),
            totp_secret: b"12345678901234567890".to_vec(),
            public_url: ORIGIN.into(),
            sessions: Mutex::new(HashMap::new()),
            login_attempts: Mutex::new(Vec::new()),
            access_attempts: Mutex::new(Vec::new()),
        };
        (dir, Arc::new(state))
    }

    async fn request(
        app: &Router,
        method: Method,
        path: &str,
        origin: Option<&str>,
        cookie: Option<&str>,
        form: &[(&str, &str)],
    ) -> Response {
        let mut builder = Request::builder().method(method).uri(path);
        if let Some(origin) = origin {
            builder = builder.header(header::ORIGIN, origin);
        }
        if let Some(cookie) = cookie {
            builder = builder.header(header::COOKIE, cookie);
        }
        let body = if form.is_empty() {
            Body::empty()
        } else {
            builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            Body::from(
                url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(form)
                    .finish(),
            )
        };
        app.clone()
            .oneshot(builder.body(body).unwrap())
            .await
            .unwrap()
    }

    async fn body(response: Response) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn between<'a>(text: &'a str, marker: &str) -> &'a str {
        text.split_once(marker)
            .unwrap()
            .1
            .split_once('\'')
            .unwrap()
            .0
    }

    #[test]
    fn url_and_html_validation() {
        assert!(checked_url("https://example.com").is_ok());
        assert!(checked_url("http://example.com").is_err());
        assert!(checked_url("https://example.com/path").is_err());
        assert_eq!(esc("<script>"), "&lt;script&gt;");
    }

    #[tokio::test]
    async fn admin_auth_and_recipient_flow() {
        let (_dir, state) = test_state();
        let app = router(state.clone());
        let guest = request(&app, Method::GET, "/", None, None, &[]).await;
        assert_eq!(guest.status(), StatusCode::OK);
        assert!(body(guest).await.contains("Вход владельца"));

        let code = auth::current_code(&state.totp_secret);
        let bad_login = request(
            &app,
            Method::POST,
            "/login",
            Some(ORIGIN),
            None,
            &[("password", "wrong"), ("code", &code)],
        )
        .await;
        assert_eq!(bad_login.status(), StatusCode::UNAUTHORIZED);
        assert!(bad_login.headers().get(header::SET_COOKIE).is_none());
        let bad_second_factor = request(
            &app,
            Method::POST,
            "/login",
            Some(ORIGIN),
            None,
            &[("password", "correct-long-password"), ("code", "abcdef")],
        )
        .await;
        assert_eq!(bad_second_factor.status(), StatusCode::UNAUTHORIZED);
        let missing_origin = request(
            &app,
            Method::POST,
            "/login",
            None,
            None,
            &[("password", "correct-long-password"), ("code", &code)],
        )
        .await;
        assert_eq!(missing_origin.status(), StatusCode::FORBIDDEN);
        let login = request(
            &app,
            Method::POST,
            "/login",
            Some(ORIGIN),
            None,
            &[("password", "correct-long-password"), ("code", &code)],
        )
        .await;
        assert_eq!(login.status(), StatusCode::SEE_OTHER);
        let set_cookie = login
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("Secure"));
        assert!(set_cookie.contains("HttpOnly"));
        assert!(set_cookie.contains("SameSite=Strict"));
        let cookie = set_cookie.split(';').next().unwrap();

        let admin = request(&app, Method::GET, "/", None, Some(cookie), &[]).await;
        let admin_html = body(admin).await;
        assert!(admin_html.contains("Панель выдачи"));
        let csrf = between(&admin_html, "name=csrf value='");
        let fields = [
            ("csrf", csrf),
            ("person", "Ivan"),
            ("device", "iPhone"),
            ("uri", URI),
            ("days", "2"),
            ("max_views", ""),
        ];
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/admin/issue",
                Some(ORIGIN),
                None,
                &fields
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/admin/issue",
                Some("https://other.example"),
                Some(cookie),
                &fields
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let mut wrong_csrf = fields;
        wrong_csrf[0] = ("csrf", "wrong");
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/admin/issue",
                Some(ORIGIN),
                Some(cookie),
                &wrong_csrf
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );

        let issued = request(
            &app,
            Method::POST,
            "/admin/issue",
            Some(ORIGIN),
            Some(cookie),
            &fields,
        )
        .await;
        assert_eq!(issued.status(), StatusCode::OK);
        assert_eq!(
            issued.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
        let issued_html = body(issued).await;
        let link = between(&issued_html, "id=link readonly value='");
        let password = between(&issued_html, "id=share-password readonly value='");
        let path = link.strip_prefix(ORIGIN).unwrap();
        let recipient = request(&app, Method::GET, path, None, None, &[]).await;
        let recipient_html = body(recipient).await;
        assert!(!recipient_html.contains(URI));
        assert!(!recipient_html.contains("QR-код VLESS"));
        assert!(!recipient_html.contains("Bypass Mode"));
        assert_eq!(
            request(
                &app,
                Method::POST,
                path,
                None,
                None,
                &[("password", password)]
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            request(
                &app,
                Method::POST,
                path,
                Some(ORIGIN),
                None,
                &[("password", "wrong")]
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
        let opened = request(
            &app,
            Method::POST,
            path,
            Some(ORIGIN),
            None,
            &[("password", password)],
        )
        .await;
        assert_eq!(opened.status(), StatusCode::OK);
        let opened_html = body(opened).await;
        assert!(opened_html.contains("QR-код VLESS"));
        assert!(opened_html.contains("example.org:443"));
        assert!(opened_html.contains("VLESS-ссылка не переносит его"));
        assert!(opened_html.contains("Bypass Mode"));
        assert!(opened_html.contains("WhatsApp, Telegram и Google Chrome"));
        assert_eq!(
            request(
                &app,
                Method::POST,
                "/admin/revoke/1",
                Some(ORIGIN),
                Some(cookie),
                &[("csrf", csrf)]
            )
            .await
            .status(),
            StatusCode::SEE_OTHER
        );
        assert_eq!(
            request(
                &app,
                Method::POST,
                path,
                Some(ORIGIN),
                None,
                &[("password", password)]
            )
            .await
            .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn expired_session_cannot_manage_shares() {
        let (_dir, state) = test_state();
        state.sessions.lock().unwrap().insert(
            "expired".into(),
            Session {
                csrf: "csrf".into(),
                expires: Instant::now() - Duration::from_secs(1),
            },
        );
        let app = router(state);
        let page = request(
            &app,
            Method::GET,
            "/",
            None,
            Some("panel_session=expired"),
            &[],
        )
        .await;
        assert!(body(page).await.contains("Вход владельца"));
        let blocked = request(
            &app,
            Method::POST,
            "/admin/revoke/1",
            Some(ORIGIN),
            Some("panel_session=expired"),
            &[("csrf", "csrf")],
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::FORBIDDEN);
    }
}
