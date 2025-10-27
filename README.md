# safeuploads

File upload hardening for Python 3.13+ services. `safeuploads` bundles a configurable validation pipeline that catches dangerous filenames, double extensions, Windows reserved names, and compressed payload attacks before you accept an upload.

## Features
- Covers filename sanitization, Unicode spoofing checks, and Windows reserved name enforcement.
- Validates extensions against allow/block lists generated from security enums.
- Performs size, compression ratio, entry count, and nested archive checks for ZIP uploads.
- Optionally inspects ZIP members for path traversal, symlinks, and archive bombs.
- Integrates with `python-magic` for MIME sniffing and falls back to standard detection when unavailable.
- Ships with defaults via `FileSecurityConfig` while allowing tuning through `SecurityLimits`.

## Installation

```bash
pip install safeuploads
```

Requirements:
- Python 3.13+
- `fastapi` (HTTPException, status, UploadFile integration)
- `python-magic` (installed automatically)
- Python's standard `logging` configuration to collect `safeuploads` diagnostics

## Quick Start

```python
from fastapi import FastAPI, UploadFile, HTTPException, status

from safeuploads import FileValidator
from safeuploads.exceptions import FileValidationError

app = FastAPI()
validator = FileValidator()


@app.post("/images")
async def upload_image(file: UploadFile):
	try:
		await validator.validate_image_file(file)
	except FileValidationError as err:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail=str(err)
		) from err

	# Continue with storage once validation passes
	return {"status": "accepted", "filename": file.filename}
```

## Configuration

- `FileSecurityConfig` holds the allow/block lists, MIME sets, and Windows reserved names.
- `SecurityLimits` governs file sizes, compression ratios, archive depth, and other thresholds.
- `validate_configuration(strict: bool = True)` audits the current configuration and returns structured `ConfigValidationError` entries.

Override limits by adjusting the dataclass before instantiating the validator:

```python
from safeuploads import FileValidator, FileSecurityConfig

config = FileSecurityConfig()
config.limits.max_image_size = 10 * 1024 * 1024  # 10 MiB cap

validator = FileValidator(config=config)
```

## Validators & Inspectors

- `UnicodeSecurityValidator` removes null bytes, control characters, and Unicode confusables.
- `ExtensionSecurityValidator` rejects compound or blocked extensions defined by `DangerousExtensionCategory` and `CompoundExtensionCategory` enums.
- `WindowsSecurityValidator` prevents reserved device names and path traversal tricks.
- `CompressionSecurityValidator` enforces size and ratio limits before accepting ZIP archives.
- `ZipContentInspector` optionally walks ZIP members to catch nested archives, symlinks, and path traversal attempts.

## Current Status (v0.1.0)

- Image and ZIP validation paths are implemented and exercised in production code.
- Configuration validation runs on import to surface misconfigurations early.
- Logging integrates with Python's `logging` package; enable the `safeuploads` logger to capture debug details.
- Packaging is ready for Poetry builds; tests and extended docs are still pending.

## Contributing

1. Clone the repository and install dependencies with Poetry or pip.
2. Add or adapt validators in `safeuploads/validators/` and inspectors in `safeuploads/inspectors/`.
3. Keep security checks isolated per class and update `FileSecurityConfig` when adding new knobs.
4. Include unit tests demonstrating both safe and malicious payload handling before opening a PR.

