import typer
import random
from datetime import datetime, timedelta
from pathlib import Path
from getpass import getpass
import secrets
import json
import uuid
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from personavault.logger import logger
from personavault.risk import compute_risk

# Rich
from rich.console import Console
from rich.table import Table

app = typer.Typer()
console = Console()

# --- Vault paths ---
VAULT_DIR = Path.home() / ".personavault"
VAULT_FILE = VAULT_DIR / "vault.db.enc"
CONFIG_FILE = VAULT_DIR / "config.json"
DATA_DIR = Path(__file__).parent / "data"

ALLOWED_TAGS = {"darkweb", "high-risk", "financial", "social", "burner", "long-term", "throwaway"}

VAULT_DATA = None  # in-memory vault

# --- Helper functions ---
def derive_key(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(secret=password.encode(), salt=salt, time_cost=2, memory_cost=102400, parallelism=8, hash_len=32, type=Type.ID)

def save_vault(password: str = None):
    global VAULT_DATA
    if VAULT_DATA is None:
        return
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    salt = bytes.fromhex(config["salt"])
    time_cost = config["time_cost"]
    memory_cost = config["memory_cost"]
    parallelism = config["parallelism"]

    if not password:
        password = getpass("Enter master password to save vault: ")

    try:
        key = hash_secret_raw(secret=password.encode(), salt=salt, time_cost=time_cost,
                              memory_cost=memory_cost, parallelism=parallelism, hash_len=32, type=Type.ID)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        encrypted = aesgcm.encrypt(nonce, json.dumps(VAULT_DATA).encode(), None)
        with open(VAULT_FILE, "wb") as f:
            f.write(nonce + encrypted)
        console.print("[green]Vault saved successfully.[/green]")
    finally:
        password = None
        key = None

def ensure_vault_loaded():
    global VAULT_DATA
    if VAULT_DATA is not None:
        return
    if not VAULT_DIR.exists() or not VAULT_FILE.exists() or not CONFIG_FILE.exists():
        console.print("[red]Vault not initialized or corrupted. Run `init` first.[/red]")
        raise typer.Exit()

    password = getpass("Enter master password: ")
    with open(CONFIG_FILE, "r") as f:
        config = json.load(f)
    salt = bytes.fromhex(config["salt"])
    key = hash_secret_raw(secret=password.encode(), salt=salt, time_cost=config["time_cost"],
                          memory_cost=config["memory_cost"], parallelism=config["parallelism"], hash_len=32, type=Type.ID)
    with open(VAULT_FILE, "rb") as f:
        file_content = f.read()
    nonce = file_content[:12]
    ciphertext = file_content[12:]
    aesgcm = AESGCM(key)
    try:
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        console.print("[bold red]Incorrect password or corrupted vault.[/bold red]")
        raise typer.Exit()
    VAULT_DATA = json.loads(decrypted.decode())
    console.print(f"[green]Vault unlocked[/green]. Loaded {len(VAULT_DATA)} identities.")
    password = None
    key = None
    decrypted = None

def load_file_lines(file_path: Path):
    if not file_path.exists():
        return []
    with open(file_path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

# --- CLI Commands ---
@app.command(help="Ping the application to check responsiveness")
def ping():
    console.print("[green]pong[/green]")

@app.command(help="Show current vault status and integrity")
def status():
    if VAULT_DIR.exists():
        console.print("Vault directory exists.")
        if VAULT_FILE.exists():
            console.print("Encrypted vault file exists.")
        else:
            console.print("[red]Vault file missing.[/red]")
    else:
        console.print("[red]Vault not initialized.[/red]")

@app.command(help="Initialize a new encrypted vault")
def init():
    if VAULT_DIR.exists():
        console.print("[yellow]Vault already exists. Delete ~/.personavault to re-init.[/yellow]")
        raise typer.Exit()
    VAULT_DIR.mkdir(mode=0o700)
    console.print(f"Created vault directory at {VAULT_DIR}")
    while True:
        password = getpass("Set master password: ")
        confirm = getpass("Confirm master password: ")
        if password == confirm:
            break
        console.print("[red]Passwords do not match. Try again.[/red]")
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    encrypted = aesgcm.encrypt(nonce, b"{}", None)
    with open(VAULT_FILE, "wb") as f:
        f.write(nonce + encrypted)
    config = {"salt": salt.hex(), "time_cost": 2, "memory_cost": 102400, "parallelism": 8}
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f)
    console.print("[green]Vault initialized successfully.[/green]")

@app.command(help="Unlock the vault with master password")
def unlock():
    ensure_vault_loaded()
    logger.info("Vault unlocked successfully")

# --- Persona CRUD Commands ---
@app.command(help="Create a new persona in the vault")
def new():
    ensure_vault_loaded()
    global VAULT_DATA

    # --- Country & Race Mapping ---
    countries = ["usa","uk","canada","germany","france","australia","brazil","south_africa"]
    COUNTRY_DISPLAY = {"usa":"USA","uk":"UK","canada":"Canada","germany":"Germany","france":"France","australia":"Australia","brazil":"Brazil","south_africa":"South Africa"}
    PHONE_CODES = {"usa":"+1","uk":"+44","canada":"+1","germany":"+49","france":"+33","australia":"+61","brazil":"+55","south_africa":"+27"}
    COUNTRY_RACE_MAP = {
        "usa":["caucasian","african","hispanic","asian","mixed"],
        "uk":["caucasian","african","asian","mixed"],
        "canada":["caucasian","african","asian","mixed"],
        "germany":["caucasian","mixed"],
        "france":["caucasian","african","mixed"],
        "australia":["caucasian","asian","mixed"],
        "brazil":["caucasian","african","hispanic","mixed"],
        "south_africa":["african","caucasian","mixed"]
    }

    country_key = random.choice(countries)
    country_display = COUNTRY_DISPLAY[country_key]
    phone_code = PHONE_CODES[country_key]
    race = random.choice(COUNTRY_RACE_MAP[country_key])

    # --- Names ---
    first_names = load_file_lines(DATA_DIR / "names" / f"{race}_first.txt") or ["Alex","Jordan","Taylor"]
    last_names = load_file_lines(DATA_DIR / "names" / f"{race}_last.txt") or ["Smith","Johnson","Brown"]
    first = random.choice(first_names)
    last = random.choice(last_names)
    full_name = f"{first} {last}"
    alias_base = f"{first}{last}"
    alias = alias_base
    while any(p['alias'] == alias for p in VAULT_DATA.values()):
        alias = f"{alias_base}{random.randint(10,99)}"

    # --- Location ---
    cities = load_file_lines(DATA_DIR / "cities" / f"{country_key}.txt") or ["Unknown City"]
    city = random.choice(cities)

    # --- Attributes ---
    genders = ["Male","Female","Non-binary"]
    blood_types = ["A+","A-","B+","B-","AB+","AB-","O+","O-"]
    email_domains = load_file_lines(DATA_DIR / "domains.txt") or ["gmail.com","yahoo.com","outlook.com","protonmail.com"]
    gender = random.choice(genders)
    blood_type = random.choice(blood_types)
    age_years = random.randint(18,65)
    dob = datetime.now() - timedelta(days=age_years*365 + random.randint(0,364))
    dob_str = dob.strftime("%Y-%m-%d")
    domain = random.choice(email_domains)
    email = f"{first.lower()}.{last.lower()}@{domain}"
    username_patterns = [f"{first.lower()}{last.lower()}", f"{first[0].lower()}{last.lower()}", f"{first.lower()}{last.lower()}{random.randint(10,99)}"]
    username = random.choice(username_patterns)
    phone = f"{phone_code}-{random.randint(100000000,999999999)}"
    address = f"{random.randint(100,999)} {random.choice(['Main St','Oak Ave','Maple Rd','Pine Ln'])}, {city}, {country_display}"
    persona_id = str(uuid.uuid4())

    persona = {
        "id": persona_id,
        "alias": alias,
        "full_name": full_name,
        "gender": gender,
        "race": race,
        "blood_type": blood_type,
        "dob": dob_str,
        "nationality": country_display,
        "location": f"{city}, {country_display}",
        "email": email,
        "usernames": [username],
        "phone": phone,
        "address": address,
        "notes": "",
        "status": "active",
        "created_at": datetime.now().isoformat(),
        "last_used": None,
        "usage": []
    }

    VAULT_DATA[persona_id] = persona
    console.print(f"[green]Persona '{alias}' created[/green] with ID [cyan]{persona_id}[/cyan].")
    save_vault()
    logger.info(f"Persona created | id={persona_id} | alias={alias}")

# --- Persona Listing ---
@app.command(help="List all personas in the vault with ID, alias, and status")
def lst():
    """List all personas in vault"""
    ensure_vault_loaded()
    if not VAULT_DATA:
        console.print("[yellow]No personas in vault.[/yellow]")
        return

    table = Table(title="Personas in Vault")
    table.add_column("ID", style="cyan")
    table.add_column("Alias", style="green")
    table.add_column("Status", style="magenta")
    for pid, persona in VAULT_DATA.items():
        table.add_row(pid, persona['alias'], persona['status'])
    console.print(table)

# --- View Persona Details ---
@app.command(help="View full details of a persona by ID")
def view(persona_id: str = typer.Option(..., prompt="Enter persona ID to view")):
    """View full details of a persona"""
    ensure_vault_loaded()
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        return

    console.print(f"[bold underline]Persona: {persona['alias']}[/bold underline]")
    for key, value in persona.items():
        console.print(f"[cyan]{key}[/cyan]: {value}")

# --- Edit Persona ---
@app.command(help="Edit editable fields (email, address, tags, phone, status, notes, alias) of a persona")
def edit(
    persona_id: str = typer.Option(..., prompt="Enter persona ID to edit"),
    field: str = typer.Option(..., prompt="Field to edit"),
    value: str = typer.Option(..., prompt="New value")
):
    """Edit an existing persona field"""
    ensure_vault_loaded()
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        raise typer.Exit()

    editable_fields = {"alias", "email", "phone", "address", "notes", "status", "tags"}
    if field not in editable_fields:
        console.print(f"[red]Field '{field}' is not editable.[/red]")
        console.print(f"Editable fields: {', '.join(editable_fields)}")
        raise typer.Exit()

    if field == "tags":
        raw_tags = [t.strip().lower() for t in value.split(",") if t.strip()]
        invalid = [t for t in raw_tags if t not in ALLOWED_TAGS]
        if invalid:
            console.print(f"[red]Invalid tags: {', '.join(invalid)}[/red]")
            console.print(f"Allowed tags: {', '.join(ALLOWED_TAGS)}")
            raise typer.Exit()
        persona[field] = list(set(raw_tags))
    else:
        persona[field] = value

    console.print(f"[green]Updated '{field}' successfully.[/green]")
    save_vault()
    logger.info(f"Persona edited | id={persona_id} | field={field}")

# --- Add Usage ---
@app.command(help="Add a usage record to a persona, automatically checking risk")
def add_usage():
    """Add a usage record to a persona with automatic risk warning"""
    ensure_vault_loaded()
    persona_id = typer.prompt("Enter persona ID")
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        raise typer.Exit()

    result = compute_risk(persona)
    risk_score, risk_level = result["score"], result["level"]

    if risk_level in ["High", "Critical"]:
        console.print(f"[bold yellow]⚠️ Warning: Persona '{persona['alias']}' has {risk_level} risk (Score: {risk_score})[/bold yellow]")
        if not typer.confirm("Do you still want to add usage?"):
            console.print("[red]Usage addition canceled due to high risk.[/red]")
            raise typer.Exit()

    platform = typer.prompt("Platform")
    username_used = typer.prompt("Username used")
    notes = typer.prompt("Notes (optional)", default="")

    usage_entry = {
        "platform": platform,
        "username": username_used,
        "date": datetime.now().strftime("%Y-%m-%d"),
        "notes": notes
    }

    persona.setdefault("usage", []).append(usage_entry)
    persona["last_used"] = datetime.now().isoformat()
    console.print("[green]Usage entry added successfully.[/green]")
    save_vault()
    logger.info(f"Usage added | id={persona_id} | platform={platform} | username={username_used}")

# --- Show Usage ---
@app.command(help="Show the usage history for a persona")
def show_usage(persona_id: str = typer.Option(..., prompt="Enter persona ID")):
    ensure_vault_loaded()
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        raise typer.Exit()

    usage_list = persona.get("usage", [])
    if not usage_list:
        console.print("[yellow]No usage records found.[/yellow]")
        return

    table = Table(title=f"Usage History for {persona['alias']}")
    table.add_column("No.", style="cyan")
    table.add_column("Platform", style="green")
    table.add_column("Username", style="magenta")
    table.add_column("Date", style="yellow")
    table.add_column("Notes", style="white")

    for idx, entry in enumerate(usage_list, 1):
        table.add_row(str(idx), entry["platform"], entry["username"], entry["date"], entry["notes"])
    console.print(table)

# --- Vault Stats ---
@app.command(help="View statistics of the vault (active, retired, burned personas etc.)")
def stats():
    ensure_vault_loaded()
    total_personas = len(VAULT_DATA)
    active_count = sum(1 for p in VAULT_DATA.values() if p.get("status") == "active")
    inactive_count = total_personas - active_count
    total_usage = sum(len(p.get("usage", [])) for p in VAULT_DATA.values())

    most_used = max(VAULT_DATA.values(), key=lambda p: len(p.get("usage", [])), default=None)
    most_used_name = most_used['alias'] if most_used and most_used.get("usage") else "None"
    most_used_count = len(most_used.get("usage", [])) if most_used else 0

    table = Table(title="Vault Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    table.add_row("Total Personas", str(total_personas))
    table.add_row("Active Personas", str(active_count))
    table.add_row("Inactive Personas", str(inactive_count))
    table.add_row("Total Usage Records", str(total_usage))
    table.add_row("Most Used Persona", f"{most_used_name} ({most_used_count} records)")
    console.print(table)

# --- List Tags ---
@app.command(help="List all allowed tags and their descriptions")
def list_tags():
    console.print("[bold underline]Allowed Tags[/bold underline]")
    for tag in sorted(ALLOWED_TAGS):
        console.print(f"- {tag}")

# --- Risk ---
@app.command(help="Calculate and display the risk score for a persona")
def risk(persona_id: str = typer.Option(..., prompt="Enter persona ID to calculate risk")):
    ensure_vault_loaded()
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        raise typer.Exit()
    result = compute_risk(persona)
    console.print(f"Persona '{persona['alias']}' Risk Score: [bold]{result['score']}[/bold] | Level: [bold red]{result['level']}[/bold red]")
    logger.info(f"Risk checked | id={persona_id} | score={result['score']} | level={result['level']}")

# --- Burn Persona ---
@app.command(help="Burn a persona immediately, with confirmation")
def burn(persona_id: str = typer.Option(..., prompt="Enter persona ID to burn/retire")):
    ensure_vault_loaded()
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        raise typer.Exit()
    result = compute_risk(persona)
    risk_level = result["level"]

    if risk_level in ["High", "Critical"] or typer.confirm(f"Risk level is {risk_level}. Burn persona anyway?"):
        persona["status"] = "burned"
        persona["last_burned"] = datetime.now().isoformat()
        console.print(f"[red]Persona '{persona['alias']}' burned.[/red]")
        logger.warning(f"Persona burned | id={persona_id}")
    else:
        console.print("[yellow]Persona remains active.[/yellow]")

    save_vault()

# --- Retire Persona ---
@app.command(help="Retire a persona safely, preserving history")
def retire(persona_id: str = typer.Option(..., prompt="Enter persona ID to retire")):
    ensure_vault_loaded()
    persona = VAULT_DATA.get(persona_id)
    if not persona:
        console.print(f"[red]Persona ID {persona_id} not found.[/red]")
        raise typer.Exit()
    persona["status"] = "retired"
    persona["last_burned"] = datetime.now().isoformat()
    console.print(f"[yellow]Persona '{persona['alias']}' retired successfully.[/yellow]")
    save_vault()
    logger.info(f"Persona retired | id={persona_id}")

# --- Search ---
@app.command(help="Search vault by tag, status, alias, or other filters")
def search(
    tag: str = typer.Option(None, help="Filter by tag"),
    status: str = typer.Option(None, help="Filter by status"),
    risk_level: str = typer.Option(None, help="Filter by risk level")
):
    ensure_vault_loaded()
    filtered = []
    for persona in VAULT_DATA.values():
        if tag and tag not in persona.get("tags", []):
            continue
        if status and persona.get("status") != status:
            continue
        if risk_level and compute_risk(persona)["level"] != risk_level:
            continue
        filtered.append(persona)

    if not filtered:
        console.print("[yellow]No personas match the filters.[/yellow]")
        return

    table = Table(title=f"Search Results ({len(filtered)} found)")
    table.add_column("ID", style="cyan")
    table.add_column("Alias", style="green")
    table.add_column("Status", style="magenta")
    table.add_column("Risk", style="red")
    table.add_column("Last Used", style="yellow")

    for p in filtered:
        last_used = p.get("last_used") or "Never"
        table.add_row(p["id"], p["alias"], p["status"], compute_risk(p)["level"], last_used)

    console.print(table)

# --- Export ---
@app.command(help="Export the entire vault or selected personas encrypted")
def export(
    output: str = typer.Option("vault_export.json"),
    ids: str = typer.Option(None),
    encrypt: bool = typer.Option(True)
):
    ensure_vault_loaded()
    if ids:
        selected_ids = [i.strip() for i in ids.split(",")]
        data_to_export = {pid: VAULT_DATA[pid] for pid in selected_ids if pid in VAULT_DATA}
        if not data_to_export:
            console.print("[yellow]No matching personas found to export.[/yellow]")
            return
    else:
        data_to_export = VAULT_DATA

    json_data = json.dumps(data_to_export, indent=2).encode("utf-8")
    if encrypt:
        password = getpass("Enter master password to encrypt export: ")
        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, json_data, None)
        with open(output, "wb") as f:
            f.write(salt + nonce + encrypted)
        console.print(f"[green]Encrypted export saved to {output}[/green]")
    else:
        with open(output, "w", encoding="utf-8") as f:
            f.write(json_data.decode())
        console.print(f"[green]Plain JSON export saved to {output}[/green]")

# --- Backup ---
@app.command(help="Backup the vault to a secure encrypted file")
def backup(output: str = typer.Option(None)):
    ensure_vault_loaded()
    if not output:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = VAULT_DIR / f"vault_backup_{timestamp}.enc"
    console.print("Backing up entire vault...")
    export(output=str(output), ids=None, encrypt=True)

if __name__ == "__main__": 
  app()
