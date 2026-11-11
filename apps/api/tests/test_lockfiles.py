"""uv.lock, poetry.lock and pnpm-lock.yaml, plus ThreatLens's own lockfiles as real samples."""

from pathlib import Path

import pytest

from threatlens_api.ingest import IngestError, parse

ROOT = Path(__file__).parents[3]


def deps(result):
    return {(d.name, d.version, d.direct) for d in result.dependencies}


def skipped(result):
    return [(s.ref, s.reason) for s in result.skipped]


# --- uv.lock ----------------------------------------------------------------------------

UV = b"""
version = 1
revision = 3

[[package]]
name = "shop"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "Flask" }, { name = "pyjwt", extra = ["crypto"] }]

[package.optional-dependencies]
s3 = [{ name = "boto3" }]

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "flask"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "werkzeug" }]

[[package]]
name = "werkzeug"
version = "2.0.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pyjwt"
version = "2.15.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "boto3"
version = "1.43.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "9.1.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "internal-lib"
version = "0.3.0"
source = { git = "https://github.com/octo/internal-lib?rev=main#abc" }

[[package]]
name = "local-thing"
version = "0.1.0"
source = { directory = "../local-thing" }
"""


def test_uv_lock_registry_packages_with_direct_ones_from_every_group():
    result = parse("uv.lock", UV)
    assert result.format == "uv.lock"
    assert deps(result) == {
        ("flask", "2.0.0", True),
        ("werkzeug", "2.0.1", False),
        ("pyjwt", "2.15.1", True),
        ("boto3", "1.43.0", True),
        ("pytest", "9.1.1", True),
    }
    assert skipped(result) == [
        ("internal-lib", "not from a package index (git, path or URL)"),
        ("local-thing", "not from a package index (git, path or URL)"),
    ]


def test_uv_workspace_members_are_not_reported_as_packages():
    lock = (
        UV
        + b"""
[[package]]
name = "worker"
version = "0.1.0"
source = { virtual = "worker" }
dependencies = [{ name = "werkzeug" }]
"""
    )
    result = parse("uv.lock", lock)
    assert ("werkzeug", "2.0.1", True) in deps(result)
    assert not any(name in ("shop", "worker") for name, _, _ in deps(result))


def test_uv_only_the_version_a_member_names_is_direct():
    lock = b"""
[[package]]
name = "shop"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "numpy", version = "1.26.4", marker = "python_version < '3.12'" },
    { name = "requests" },
]

[[package]]
name = "numpy"
version = "1.26.4"
source = { registry = "x" }

[[package]]
name = "numpy"
version = "2.1.0"
source = { registry = "x" }

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "x" }
"""
    assert deps(parse("uv.lock", lock)) == {
        ("numpy", "1.26.4", True),
        ("numpy", "2.1.0", False),
        ("requests", "2.32.3", True),
    }


def test_uv_two_versions_of_one_package_are_both_kept():
    lock = b"""
[[package]]
name = "numpy"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "numpy"
version = "2.1.0"
source = { registry = "https://pypi.org/simple" }
"""
    assert {v for _, v, _ in deps(parse("uv.lock", lock))} == {"1.26.4", "2.1.0"}


@pytest.mark.parametrize(
    ("lock", "reason"),
    [
        (b'[[package]]\nversion = "1"\nsource = { registry = "x" }\n', "no package name"),
        (b'[[package]]\nname = "a"\nsource = { registry = "x" }\n', "no version in lockfile"),
        (b'[[package]]\nname = "a"\nversion = "1"\n', "not from a package index"),
        (b'[[package]]\nname = "a"\nversion = "1"\nsource = "odd"\n', "not from a package index"),
        (b'[[package]]\nname = "a b"\nversion = "1"\nsource = { registry = "x" }\n', "invalid"),
    ],
)
def test_uv_odd_entries_are_skipped_with_a_reason(lock, reason):
    result = parse("uv.lock", lock)
    assert result.dependencies == []
    assert reason in result.skipped[0].reason


def test_uv_odd_member_groups_do_not_crash():
    lock = b"""
[[package]]
name = "shop"
version = "0.1.0"
source = { editable = "." }
dependencies = "nope"
optional-dependencies = "nope"
dev-dependencies = { dev = "nope", other = [1, { name = 2 }, { name = "ok" }] }

[[package]]
name = "ok"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""
    assert deps(parse("uv.lock", lock)) == {("ok", "1.0.0", True)}


# --- poetry.lock ------------------------------------------------------------------------

POETRY = b"""
[[package]]
name = "Django"
version = "4.2.1"
optional = false

[[package]]
name = "internal"
version = "1.0.0"

[package.source]
type = "legacy"
url = "https://pypi.example.com/simple"
reference = "corp"

[[package]]
name = "mylib"
version = "0.1.0"

[package.source]
type = "git"
url = "https://github.com/octo/mylib.git"
reference = "main"

[metadata]
lock-version = "2.1"
"""


def test_poetry_lock_index_packages_only():
    result = parse("poetry.lock", POETRY)
    assert result.format == "poetry.lock"
    assert deps(result) == {("django", "4.2.1", True), ("internal", "1.0.0", True)}
    assert skipped(result) == [("mylib", "not from a package index (git, path or URL)")]


@pytest.mark.parametrize(
    "lock",
    [b'[[package]]\nname = "a"\n', b'[[package]]\nversion = "1"\n', b"[[package]]\nname = 1\n"],
)
def test_poetry_entries_without_name_or_version_are_skipped(lock):
    result = parse("poetry.lock", lock)
    assert result.dependencies == []
    assert result.skipped[0].reason == "no name or version in lockfile"


# --- TOML safety -------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["uv.lock", "poetry.lock"])
@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"[[package\n", "Invalid TOML"),
        (b"package = 3\n", r"has no \[\[package\]\] list"),
        pytest.param(
            b"x = " + b"[" * 100_000 + b"]" * 100_000 + b"\n",
            "nested too deeply|Invalid TOML",
            id="deep",
        ),
    ],
)
def test_bad_toml_is_refused_cleanly(name, data, message):
    with pytest.raises(IngestError, match=message):
        parse(name, data)


@pytest.mark.parametrize("name", ["uv.lock", "poetry.lock"])
def test_a_toml_file_without_packages_is_empty(name):
    result = parse(name, b"version = 1\n")
    assert result.dependencies == [] and result.skipped == []


# --- pnpm-lock.yaml -----------------------------------------------------------------------

PNPM9 = b"""lockfileVersion: '9.0'

importers:
  .: {}
  apps/web:
    dependencies:
      next:
        specifier: 16.4.3
        version: 16.4.3(react@19.3.0)
      '@base-ui/react':
        specifier: ^1.9.0
        version: 1.9.0(react@19.3.0)
      local-ui:
        specifier: workspace:*
        version: link:../ui
    devDependencies:
      vitest:
        specifier: ^5.0.5
        version: 5.0.5

packages:
  next@16.4.3:
    resolution: {integrity: sha512-x}
  '@base-ui/react@1.9.0':
    resolution: {integrity: sha512-x}
  '@next/env@16.4.3':
    resolution: {integrity: sha512-x}
  vitest@5.0.5:
    resolution: {integrity: sha512-x}
  react@19.3.0:
    resolution: {integrity: sha512-x}
  mylib@https://codeload.github.com/octo/mylib/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/octo/mylib/tar.gz/abc}
  local@file:../local:
    resolution: {directory: ../local, type: directory}

snapshots:
  next@16.4.3(react@19.3.0):
    dependencies:
      '@next/env': 16.4.3
"""


def test_pnpm_v9_packages_with_direct_ones_from_every_project():
    result = parse("pnpm-lock.yaml", PNPM9)
    assert result.format == "pnpm-lock.yaml"
    assert deps(result) == {
        ("next", "16.4.3", True),
        ("@base-ui/react", "1.9.0", True),
        ("@next/env", "16.4.3", False),
        ("vitest", "5.0.5", True),
        ("react", "19.3.0", False),
    }
    assert skipped(result) == [
        ("mylib@https://codeload.github.com/octo/mylib/tar.gz/abc", "not from the npm registry"),
        ("local@file:../local", "not from the npm registry"),
    ]


PNPM6 = b"""lockfileVersion: '6.0'

dependencies:
  express:
    specifier: ^4.18.0
    version: 4.18.2

devDependencies:
  '@types/express':
    specifier: ^4.17.0
    version: 4.17.21

packages:

  /express@4.18.2:
    resolution: {integrity: sha512-x}
    dev: false

  /@types/express@4.17.21:
    resolution: {integrity: sha512-x}
    dev: true

  /body-parser@1.20.1(supports-color@8.1.1):
    resolution: {integrity: sha512-x}
    dev: false
"""


def test_pnpm_v6_single_project():
    assert deps(parse("pnpm-lock.yaml", PNPM6)) == {
        ("express", "4.18.2", True),
        ("@types/express", "4.17.21", True),
        ("body-parser", "1.20.1", False),
    }


@pytest.mark.parametrize(
    ("data", "message"),
    [
        (b"lockfileVersion: 5.4\npackages: {}\n", "versions 6 and 9"),
        (b"packages: {}\n", "versions 6 and 9"),
        (b"- a\n- b\n", "must be a YAML mapping"),
        (b"lockfileVersion: '9.0'\npackages: [1, 2]\n", "packages must be a mapping"),
        (b"lockfileVersion: '9.0'\npackages: {a: [\n", "Invalid YAML"),
        (
            b"lockfileVersion: '9.0'\nx: !!python/object/apply:os.system ['echo hi']\n",
            "Invalid YAML",
        ),
        pytest.param(
            b"lockfileVersion: '9.0'\nx: " + b"[" * 100_000 + b"]" * 100_000 + b"\n",
            "nested too deeply",
            id="deep",
        ),
        # 4.5 MB, under the size cap. This one and the one above crash the whole process
        # (C stack overflow) with libyaml's loader; see _load_yaml.
        pytest.param(
            b"lockfileVersion: '9.0'\na:\n"
            + b"".join(b" " * i + b"k%d:\n" % i for i in range(1, 3000)),
            "nested too deeply",
            id="deep-indents",
        ),
    ],
)
def test_bad_pnpm_files_are_refused_cleanly(data, message):
    with pytest.raises(IngestError, match=message):
        parse("pnpm-lock.yaml", data)


def test_pnpm_odd_keys_are_skipped_not_crashed():
    data = b"""lockfileVersion: '9.0'
importers:
  .: {dependencies: {a: 7, b: {version: [1]}, 3: {version: '1.0.0'}}}
  web: nope
packages:
  noversion: {}
  '@scope/only': {}
  ok@1.0.0: {}
  123: {}
"""
    result = parse("pnpm-lock.yaml", data)
    assert deps(result) == {("ok", "1.0.0", False)}
    assert [r for r, _ in skipped(result)] == ["noversion", "@scope/only"]


def test_pnpm_without_packages_is_empty():
    result = parse("pnpm-lock.yaml", b"lockfileVersion: '9.0'\nimporters:\n  .: {}\n")
    assert result.dependencies == [] and result.skipped == []


def _alias_bomb(levels, merge):
    keys = ", ".join(f"k{i}: 1" for i in range(10))
    lines = ["lockfileVersion: '9.0'", f"m0: &m0 {{{keys}}}"]
    for i in range(1, levels + 1):
        refs = ", ".join([f"*m{i - 1}"] * 10)
        lines.append(f"m{i}: &m{i} {{<<: [{refs}]}}" if merge else f"m{i}: &m{i} [{refs}]")
    return ("\n".join(lines) + "\npackages: {ok@1.0.0: {}}\n").encode()


@pytest.mark.parametrize(
    "data",
    [
        # Merge keys copy every merged pair: 5 levels took 0.9 s, 7 took 107 s, 8 runs out
        # of memory. 5 here, so a regression fails fast instead of hanging the run.
        pytest.param(_alias_bomb(5, merge=True), id="merge-keys"),
        pytest.param(_alias_bomb(9, merge=False), id="sequences"),
        pytest.param(b"lockfileVersion: '9.0'\na: &a 1\nb: *a\n", id="one-alias"),
    ],
)
def test_pnpm_aliases_are_refused(data):
    with pytest.raises(IngestError, match="aliases"):
        parse("pnpm-lock.yaml", data)


def test_pnpm_merge_key_without_aliases_still_loads():
    data = b"lockfileVersion: '9.0'\nx: {<<: {a: 1}, b: 2}\npackages: {ok@1.0.0: {}}\n"
    assert deps(parse("pnpm-lock.yaml", data)) == {("ok", "1.0.0", False)}


def test_pnpm_npm_aliases_are_direct_under_the_real_name():
    v9 = b"""lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      string-width-cjs:
        specifier: npm:string-width@^4.2.0
        version: string-width@4.2.3
      '@x/y-old': {specifier: 'npm:@x/y@1', version: '@x/y@1.0.0(react@19.0.0)'}
packages:
  string-width@4.2.3: {}
  '@x/y@1.0.0': {}
"""
    v6 = b"""lockfileVersion: '6.0'
dependencies:
  string-width-cjs:
    specifier: npm:string-width@^4.2.0
    version: /string-width@4.2.3
packages:
  /string-width@4.2.3: {}
"""
    assert deps(parse("pnpm-lock.yaml", v9)) == {
        ("string-width", "4.2.3", True),
        ("@x/y", "1.0.0", True),
    }
    assert deps(parse("pnpm-lock.yaml", v6)) == {("string-width", "4.2.3", True)}


def test_pnpm_v6_git_and_tarball_keys_are_not_from_the_registry():
    data = b"""lockfileVersion: '6.0'
packages:
  github.com/octo/mylib/abc123: {}
  registry.example.com/x/-/x-1.0.0.tgz: {}
  /ok@1.0.0: {}
"""
    result = parse("pnpm-lock.yaml", data)
    assert deps(result) == {("ok", "1.0.0", False)}
    assert {reason for _, reason in skipped(result)} == {"not from the npm registry"}


# --- ThreatLens's own lockfiles -----------------------------------------------------------


def test_threatlens_own_uv_lock():
    result = parse("uv.lock", (ROOT / "apps" / "api" / "uv.lock").read_bytes())
    direct = {d.name for d in result.dependencies if d.direct}
    assert {"fastapi", "boto3", "pyjwt", "pyyaml", "pytest", "ruff"} <= direct
    assert "starlette" not in direct  # comes with fastapi
    assert len(result.dependencies) > 40 and result.skipped == []


def test_threatlens_own_pnpm_lock():
    result = parse("pnpm-lock.yaml", (ROOT / "pnpm-lock.yaml").read_bytes())
    direct = {d.name for d in result.dependencies if d.direct}
    assert {"next", "react", "zod", "vitest", "@base-ui/react"} <= direct
    assert "@next/env" not in direct
    assert len(result.dependencies) > 500 and result.skipped == []


def test_unsupported_file_message_lists_the_new_formats():
    with pytest.raises(IngestError, match="pnpm-lock.yaml, uv.lock or poetry.lock"):
        parse("yarn.lock", b"x")


def test_uv_names_match_whatever_their_spelling():
    lock = b"""
[[package]]
name = "shop"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "py-jwt" }]

[[package]]
name = "Py_JWT"
version = "2.15.1"
source = { registry = "https://pypi.org/simple" }
"""
    assert deps(parse("uv.lock", lock)) == {("py-jwt", "2.15.1", True)}


@pytest.mark.parametrize("key", ["@1.0.0", "x@", "/@1.0.0(peer@1)"])
def test_pnpm_keys_missing_a_name_or_version(key):
    data = b"lockfileVersion: '9.0'\npackages:\n  '" + key.encode() + b"': {}\n"
    assert skipped(parse("pnpm-lock.yaml", data)) == [
        (key, "could not read package name and version")
    ]
