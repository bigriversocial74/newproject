from pathlib import Path

path = Path(__file__).resolve().parent / "build-phase13-homeserver-contract-temp.py"
text = path.read_text()
old = '''catalog = replace_once(
    catalog,
    "                 (public_id,product_id,version,channel,status,release_notes_hash,emergency_override,created_at,updated_at)\\n                  VALUES (:public,:product,:version,:channel,'draft',:notes,:emergency,UTC_TIMESTAMP(),UTC_TIMESTAMP())",
    "                 (public_id,product_id,version,channel,status,release_notes_hash,release_notes,emergency_override,created_at,updated_at)\\n                  VALUES (:public,:product,:version,:channel,'draft',:notes_hash,:release_notes,:emergency,UTC_TIMESTAMP(),UTC_TIMESTAMP())",
    "release-note persistence SQL",
)
catalog = replace_once(
    catalog,
    "                'notes' => hash('sha256', $releaseNotes),",
    "                'notes_hash' => hash('sha256', $releaseNotes),\\n                'release_notes' => substr($releaseNotes, 0, 20000),",
    "release-note persistence parameters",
)
catalog = replace_once(
    catalog,
    "                 (release_id,platform,architecture,storage_reference,sha256,size_bytes,created_at)\\n                  VALUES (:release,:platform,:architecture,:storage,:sha,:size,UTC_TIMESTAMP())",
    "                 (release_id,platform,architecture,storage_reference,sha256,size_bytes,authenticode_thumbprint,created_at)\\n                  VALUES (:release,:platform,:architecture,:storage,:sha,:size,:thumbprint,UTC_TIMESTAMP())",
    "release-artifact persistence SQL",
)
'''
new = '''release_sql_pattern = re.compile(
    r"(?P<indent>\\s*)\\(public_id,product_id,version,channel,status,release_notes_hash,emergency_override,created_at,updated_at\\)\\n"
    r"(?P<values>\\s*)VALUES \\(:public,:product,:version,:channel,'draft',:notes,:emergency,UTC_TIMESTAMP\\(\\),UTC_TIMESTAMP\\(\\)\\)"
)
catalog, count = release_sql_pattern.subn(
    r"\\g<indent>(public_id,product_id,version,channel,status,release_notes_hash,release_notes,emergency_override,created_at,updated_at)\\n"
    r"\\g<values>VALUES (:public,:product,:version,:channel,'draft',:notes_hash,:release_notes,:emergency,UTC_TIMESTAMP(),UTC_TIMESTAMP())",
    catalog,
    count=1,
)
if count != 1:
    raise SystemExit("release-note persistence SQL was not found")
catalog = replace_once(
    catalog,
    "                'notes' => hash('sha256', $releaseNotes),",
    "                'notes_hash' => hash('sha256', $releaseNotes),\\n                'release_notes' => substr($releaseNotes, 0, 20000),",
    "release-note persistence parameters",
)
artifact_sql_pattern = re.compile(
    r"(?P<indent>\\s*)\\(release_id,platform,architecture,storage_reference,sha256,size_bytes,created_at\\)\\n"
    r"(?P<values>\\s*)VALUES \\(:release,:platform,:architecture,:storage,:sha,:size,UTC_TIMESTAMP\\(\\)\\)"
)
catalog, count = artifact_sql_pattern.subn(
    r"\\g<indent>(release_id,platform,architecture,storage_reference,sha256,size_bytes,authenticode_thumbprint,created_at)\\n"
    r"\\g<values>VALUES (:release,:platform,:architecture,:storage,:sha,:size,:thumbprint,UTC_TIMESTAMP())",
    catalog,
    count=1,
)
if count != 1:
    raise SystemExit("release-artifact persistence SQL was not found")
'''
if old not in text:
    raise SystemExit("Phase 13 exact SQL patch block was not found")
path.write_text(text.replace(old, new, 1))
