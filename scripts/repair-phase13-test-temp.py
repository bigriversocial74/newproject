from pathlib import Path

path = Path(__file__).resolve().parent / "build-phase13-homeserver-contract-temp.py"
text = path.read_text()
replacements = {
    "$assert(str_contains($registry, \"'algorithm' => $signed['algorithm']\"), 'Lease response omits algorithm.');":
        "$assert(str_contains($registry, \"'algorithm' => \\$signed['algorithm']\"), 'Lease response omits algorithm.');",
    "$assert(str_contains($bootstrap, \"$config['releases']['signing_private_key_base64']\"), 'Lease signer does not use the release authority keypair.');":
        "$assert(str_contains($bootstrap, \"\\$config['releases']['signing_private_key_base64']\"), 'Lease signer does not use the release authority keypair.');",
}
for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f"Phase 13 PHP fixture literal was not found: {old}")
    text = text.replace(old, new, 1)
path.write_text(text)
