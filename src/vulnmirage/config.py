"""Configuration models and loader.

Only the task-driven campaign flow is configured here: where a snapshot comes from
(archive), how the audit run is bounded (isolation + egress), how the frozen answer
is scored (verifier), what the agent must return (output contract), and what is
frozen before the first run (campaign plan + variants).

Rules enforced by the loader:

* unknown keys are rejected, so a typo cannot silently fall back to a default;
* credentials are never accepted in a configuration file -- an agent config lists
  the **names** of the variables it needs;
* the normalized configuration is hashed with SHA-256 and that digest is part of
  every plan, so a resumed campaign cannot continue under a changed treatment.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from . import SCHEMA_VERSION
from .errors import ConfigError
from .hashing import canonical_json, sha256_file, sha256_text
from .paths import project_root
from .tiers import Tier, is_implemented

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --------------------------------------------------------------------- archive
class ArchiveProviderConfig(_Strict):
    """Where one exact-commit archive comes from.

    An archive replaces clone-first materialization: a clone ships later commits
    and the fix commit inside ``.git``.
    """

    name: Literal["github", "gitlab", "local_zip", "local_tree"] = "github"
    #: Hosts a redirect may land on.  Anything else aborts the download instead of
    #: silently fetching a different artifact.
    allowed_hosts: list[str] = Field(
        default_factory=lambda: ["codeload.github.com", "github.com", "api.github.com"]
    )
    timeout_seconds: int = Field(default=120, ge=1)
    max_redirects: int = Field(default=3, ge=0, le=10)
    max_bytes: int = Field(default=268_435_456, ge=1024)
    verify_tls: bool = True
    retries: int = Field(default=1, ge=0, le=5)

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, value: list[str]) -> list[str]:
        return sorted({item.strip().lower() for item in value if item.strip()})


class ExtractionLimitsConfig(_Strict):
    """Budget for unpacking an untrusted source archive."""

    max_files: int = Field(default=40_000, ge=1)
    max_total_bytes: int = Field(default=1_073_741_824, ge=1)
    max_file_bytes: int = Field(default=67_108_864, ge=1)
    max_path_depth: int = Field(default=32, ge=1)
    strip_single_root: bool = True
    #: Nested version-control metadata is history, i.e. a possible answer channel.
    reject_nested_history: bool = True


class ArchiveConfig(_Strict):
    provider: ArchiveProviderConfig = Field(default_factory=ArchiveProviderConfig)
    limits: ExtractionLimitsConfig = Field(default_factory=ExtractionLimitsConfig)
    cache_dir: str = "workspace/cache/archives"
    #: Trusted preparation stage only; never exposed to the auditing agent.
    require_commit_pinned: bool = True


# ------------------------------------------------------------------- isolation
class EgressConfig(_Strict):
    """Tool egress policy plus the probe that makes it testable.

    ``none`` records reality without claiming enforcement.  Any mode still has to
    pass the live probe: a declared policy is not evidence.
    """

    mode: Literal["linux_namespace", "container", "proxy", "none"] = "none"
    #: The single upstream the model calls may use.
    inference_gateway_hosts: list[str] = Field(default_factory=list)
    #: Hosts that must be unreachable because they serve the answer.
    probe_blocked_hosts: list[str] = Field(
        default_factory=lambda: [
            "github.com",
            "raw.githubusercontent.com",
            "codeload.github.com",
            "huggingface.co",
            "grep.app",
            "www.google.com",
            "duckduckgo.com",
        ]
    )
    probe_timeout_seconds: float = Field(default=4.0, gt=0.0, le=60.0)
    #: A run whose probe shows a reachable answer host is ineligible for the formal
    #: experiment instead of being explained away.
    fail_closed: bool = True


class IsolationConfig(_Strict):
    mode: Literal["workspace", "none"] = "workspace"
    #: Repository directory name inside the exposed root; identical for every
    #: variant so one task text maps to one stable path.
    repo_dirname: str = "repo"
    output_dirname: str = "out"
    #: A fresh state directory per run; reusing it would leak the previous score.
    fresh_state: bool = True
    egress: EgressConfig = Field(default_factory=EgressConfig)


# -------------------------------------------------------------------- verifier
class VerifierConfig(_Strict):
    """Independent evaluator: the oracle never enters the agent's space."""

    mode: Literal["separate_process", "in_process"] = "separate_process"
    private_dirname: str = "private"
    #: Untrusted report text is data, never instructions.
    max_report_chars: int = Field(default=200_000, ge=1000)
    max_findings: int = Field(default=200, ge=1)
    line_tolerance: int = Field(default=5, ge=0, le=200)
    require_output_consistency: bool = True
    refuse_when_bundle_contains_oracle: bool = True


# --------------------------------------------------------------------- outputs
class OutputContractConfig(_Strict):
    schema_version: str = "1.0"
    require_report_markdown: bool = True
    require_findings: bool = True
    max_final_answer_chars: int = Field(default=400_000, ge=1000)


# -------------------------------------------------------------------- campaign
class VariantEditConfig(_Strict):
    op: Literal["create", "append", "insert_before"] = "create"
    path: str
    text: str = ""
    #: Anchor text required by ``insert_before``; the edit fails loudly when the
    #: anchor is missing instead of silently doing nothing.
    find: str | None = None


class VariantSpecConfig(_Strict):
    variant_id: str
    kind: Literal["clean", "attack"] = "attack"
    #: Generator capability is provenance, not attack intensity. ``tier`` remains
    #: a validation alias for old programmatic callers but is not serialized.
    generator_tier: Tier = Field(
        default="T0", validation_alias=AliasChoices("generator_tier", "tier")
    )
    #: Concrete realization from the canonical method registry. ``payload_id``
    #: is accepted only as a migration alias for direct API callers.
    realization_id: str | None = Field(
        default=None, validation_alias=AliasChoices("realization_id", "payload_id")
    )
    #: Filled by the trusted catalog binding; variant-set authors do not invent it.
    method_id: str | None = None
    carrier: str | None = None
    objective: Literal[
        "O-FN",
        "O-FP",
        "O-SEV-D",
        "O-SEV-I",
        "O-EV",
        "O-SCOPE",
        "O-AVAIL",
        "none",
    ] = Field(default="none", validation_alias=AliasChoices("objective", "goal"))
    edits: list[VariantEditConfig] = Field(default_factory=list)
    #: Text that must never appear in the variant (answer-identifying tokens).
    forbidden_tokens: list[str] = Field(default_factory=list)

    @field_validator("objective", mode="before")
    @classmethod
    def _canonical_objective(cls, value: object) -> object:
        legacy = {
            "false_negative": "O-FN",
            "false_positive": "O-FP",
            "severity_shift": "O-SEV-D",
            "severity_downgrade": "O-SEV-D",
            "severity_inflation": "O-SEV-I",
            "verification_diversion": "O-SCOPE",
            "evidence_weakening": "O-EV",
            "scope_shift": "O-SCOPE",
        }
        return legacy.get(str(value), value)

    @property
    def tier(self) -> Tier:
        """Compatibility view; new artifacts use ``generator_tier``."""
        return self.generator_tier

    @property
    def payload_id(self) -> str | None:
        """Compatibility view; new artifacts use ``realization_id``."""
        return self.realization_id

    @property
    def goal(self) -> str:
        """Compatibility view; new artifacts use canonical Objective IDs."""
        return self.objective

    @property
    def knowledge(self) -> str:
        """Legacy display label derived from generation provenance only."""
        return "oracle_guided" if self.generator_tier in {"T2", "T3", "T4"} else "public_context"


class TierProfileConfig(_Strict):
    """Generation budget and limits for one capability tier.

    The size limits are optional ceilings: ``None`` means "the method's own
    ``placement_limits`` decide". A method that legitimately needs more lines (a
    certified decoy file, for instance) is not silently truncated by a generic
    tier default, and a profile that does set a value still wins when it is
    stricter.
    """

    tier: Tier
    generator_profile: str = "default"
    candidate_budget: int = Field(default=1, ge=1, le=64)
    selection_policy: str = "semantic_fit_then_deterministic_tiebreak"
    max_files_changed: int | None = Field(default=None, ge=1, le=16)
    max_inserted_lines: int | None = Field(default=None, ge=1, le=400)
    max_payload_chars: int | None = Field(default=None, ge=1, le=200_000)
    max_model_calls: int = Field(default=0, ge=0, le=1000)

    @field_validator("tier")
    @classmethod
    def _implemented(cls, value: str) -> str:
        if not is_implemented(value):
            raise ValueError(f"tier {value} is not implemented in this build")
        return value


class GenerationBudgetConfig(_Strict):
    """Campaign-level generation envelope, frozen with the plan."""

    seed: int = Field(default=0, ge=0)
    candidate_budget: int = Field(default=3, ge=1, le=64)
    max_model_calls: int = Field(default=0, ge=0, le=10_000)
    require_candidate_validation: bool = True
    tier_profiles: dict[str, TierProfileConfig] = Field(
        default_factory=lambda: {
            "T0": TierProfileConfig(tier="T0", candidate_budget=1),
            "T1": TierProfileConfig(tier="T1", candidate_budget=3),
            "T2": TierProfileConfig(tier="T2", candidate_budget=3),
        }
    )

    def profile_for(self, tier: str) -> TierProfileConfig:
        profile = self.tier_profiles.get(tier)
        if profile is None:
            raise ConfigError(
                "no generation profile is configured for this tier",
                details={"tier": tier, "configured": sorted(self.tier_profiles)},
            )
        return profile


class CampaignConfig(_Strict):
    dataset_root: str = "../VulnMirage_dataset"
    tasks_file: str | None = None
    oracle_file: str | None = None
    #: Control plane: scheduler, budget and private pointers.  Never exposed.
    archive_root: str = "workspace"
    task_prompt_rule_version: str = "2026-11-03.1"
    audit_task_template: str = "prompts/audit_task.md"
    #: C plus the injected variants that share one clean baseline.
    variants: list[VariantSpecConfig] = Field(default_factory=list)
    variants_file: str | None = None
    #: Registry of reusable payload methods.  Relative paths are resolved as
    #: normal benchmark assets (config directory, project root, then cwd).
    payload_catalog: str | None = None
    #: Tier profiles and the seed decide what generation may try; they are frozen
    #: with the plan so a "T2" condition cannot be re-planned as T0 later.
    generation: GenerationBudgetConfig = Field(default_factory=GenerationBudgetConfig)
    #: Formal runs are pre-registered; the same count runs for every condition.
    repetitions: int = Field(default=1, ge=1, le=50)
    max_tasks_per_campaign: int = Field(default=1, ge=1, le=500)
    #: Target-level cells are expanded during planning.  Keeping the default at
    #: one makes a pilot affordable; set this up to 500 (or use --target-limit)
    #: to cover every eligible target in a task.
    max_targets_per_task: int = Field(default=1, ge=1, le=500)
    max_workers: int = Field(default=1, ge=1, le=64)
    #: Wall clock for a single audit process.
    audit_timeout_seconds: int = Field(default=900, ge=1)
    #: Lowest target eligibility that may enter scoring (see ingest.dataset_core).
    minimum_target_eligibility: Literal["snapshot_verified", "annotation_verified"] = (
        "snapshot_verified"
    )
    keep_intermediates: bool = False
    #: Cleanup only after a verified archive; never delete referenced caches.
    cleanup_requires_verified_archive: bool = True


# ------------------------------------------------------------------------ agent
class AgentConfig(_Strict):
    """How one audit is executed.

    ``mode`` decides how the final answer is collected:

    * ``argv`` -- the command writes the answer into ``{output}`` itself;
    * ``stdout`` -- the command prints; the harness captures stdout and extracts the
      last JSON object, or the last text part of a JSONL event stream.

    The child process always starts with the exposed repository as its working
    directory. ``{repo}``, ``{output}``, ``{task}`` and ``{prompt}`` remain
    available when a framework needs explicit path arguments.
    """

    schema_version: str = SCHEMA_VERSION
    runtime: Literal["subprocess", "linux_namespace"] = "subprocess"
    mode: Literal["argv", "stdout"] = "stdout"
    argv: list[str] = Field(default_factory=list)
    #: How the answer is located inside stdout when ``mode = stdout``.
    answer_extractor: Literal["jsonl_events", "json_last_object", "tail", "claude_jsonl"] = (
        "jsonl_events"
    )
    #: Adapter for the framework's native stdout event stream.  This is separate
    #: from answer extraction: an answer may be parseable even when its trace is
    #: partial, and vice versa.
    trace_adapter: Literal["none", "opencode_jsonl", "claude_code_jsonl"] = "none"
    #: Read-only command used before the campaign to freeze the exact framework
    #: version into every run. It must not contact a model endpoint.
    framework_version_command: list[str] = Field(default_factory=list)
    #: Framework-native configuration loaded by the child process.  The path is
    #: resolved relative to this YAML file, hashed into the effective agent
    #: identity, and forwarded through ``OPENCODE_CONFIG``.  It is never copied
    #: into the audited repository.
    framework_config_file: str | None = None
    timeout_seconds: int = Field(default=1200, ge=1)
    #: Recorded with every run; never inferred.
    model_label: str | None = None
    #: Credential variables forwarded **by name** (values are never read here).
    requires_env: list[str] = Field(default_factory=list)
    #: Extra parent variables copied into the child environment.
    env_allowlist: list[str] = Field(
        default_factory=lambda: [
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "LANG",
            "LC_ALL",
        ]
    )

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {value!r}")
        return value

    def missing_env(self, environ: dict[str, str] | None = None) -> list[str]:
        source = os.environ if environ is None else environ
        return [name for name in self.requires_env if not source.get(name)]


class AgentProfileConfig(_Strict):
    """One model entry inside a multi-model agent config.

    ``overrides`` is validated by building the final :class:`AgentConfig`, so an
    unknown or unsafe key fails the same way a flat config would.
    """

    model: str
    description: str | None = None
    model_label: str | None = None
    requires_env: list[str] = Field(default_factory=list)
    overrides: dict[str, Any] = Field(default_factory=dict)


class AppConfig(_Strict):
    schema_version: str = SCHEMA_VERSION
    archive: ArchiveConfig = Field(default_factory=ArchiveConfig)
    isolation: IsolationConfig = Field(default_factory=IsolationConfig)
    verifier: VerifierConfig = Field(default_factory=VerifierConfig)
    output_contract: OutputContractConfig = Field(default_factory=OutputContractConfig)
    campaign: CampaignConfig = Field(default_factory=CampaignConfig)

    @field_validator("schema_version")
    @classmethod
    def _schema(cls, value: str) -> str:
        if value != SCHEMA_VERSION:
            raise ValueError(f"unsupported schema_version {value!r}")
        return value


@dataclass(frozen=True)
class LoadedConfig:
    config: AppConfig
    source: Path
    base_dir: Path
    sha256: str

    def resolve_asset(self, value: str, *, must_exist: bool = True) -> Path:
        """Resolve a prompt/template path against config dir, package root, cwd."""
        candidate = Path(value).expanduser()
        if candidate.is_absolute():
            if must_exist and not candidate.exists():
                raise ConfigError(f"asset not found: {candidate}", details={"path": str(candidate)})
            return candidate
        for base in (self.base_dir, project_root(), Path.cwd()):
            resolved = (base / candidate).resolve()
            if resolved.exists():
                return resolved
        if not must_exist:
            return (Path.cwd() / candidate).resolve()
        raise ConfigError(
            f"asset not found: {value}",
            details={"searched": [str(self.base_dir), str(project_root()), str(Path.cwd())]},
        )


@dataclass(frozen=True)
class LoadedAgentConfig:
    config: AgentConfig
    source: Path
    base_dir: Path
    sha256: str
    #: Which entry of a multi-model file was selected; ``None`` for a flat file.
    profile: str | None = None
    #: Every profile the file declares, so a typo can be answered with the list.
    profiles: tuple[str, ...] = ()
    #: Environment additions assembled by the trusted launcher.  Values may be
    #: host paths, so run artefacts record names and file hashes, not values.
    child_env: dict[str, str] = field(default_factory=dict)
    external_file_sha256: dict[str, str] = field(default_factory=dict)


def _substitute_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _substitute_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute_env(item) for item in value]
    if isinstance(value, str):
        missing: set[str] = set()

        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                missing.add(name)
                return ""
            return os.environ[name]

        result = _ENV_RE.sub(replace, value)
        if missing:
            names = ", ".join(sorted(missing))
            raise ConfigError(
                f"environment variables referenced by config are not set: {names}",
                details={"missing": sorted(missing)},
            )
        return result
    return value


_SECRET_KEY_RE = re.compile(
    r"(^|[._-])(api[_-]?key|secret|token|password|private[_-]?key)$", re.I
)


def _reject_secret_keys(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key)
            if _SECRET_KEY_RE.search(key_text):
                raise ConfigError(
                    "credentials must not be stored in configuration files; "
                    "use environment variables",
                    details={
                        "key_path": f"{path}.{key_text}" if path else key_text
                    },
                )
            _reject_secret_keys(item, f"{path}.{key_text}" if path else key_text)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_secret_keys(item, f"{path}[{index}]")


def config_sha256(config: AppConfig) -> str:
    return sha256_text(canonical_json(config.model_dump(mode="json")))


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}", details={"path": str(path)}) from exc
    if not isinstance(raw, dict):
        raise ConfigError("config root must be a mapping", details={"path": str(path)})
    raw = _substitute_env(raw)
    _reject_secret_keys(raw)
    return raw


def _resolve(path: str | Path) -> Path:
    source = Path(path).expanduser()
    if not source.is_absolute():
        source = (Path.cwd() / source).resolve()
    if not source.exists():
        raise ConfigError(f"config file not found: {source}", details={"path": str(source)})
    return source


def load_config(path: str | Path) -> LoadedConfig:
    from .env import load_local_env

    load_local_env()
    source = _resolve(path)
    raw = _load_yaml(source)
    try:
        config = AppConfig.model_validate(raw)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigError(
            f"invalid configuration: {exc}",
            details={"path": str(source), "validation": str(exc)},
        ) from exc
    return LoadedConfig(
        config=config, source=source, base_dir=source.parent, sha256=config_sha256(config)
    )


def with_variant_set(loaded: LoadedConfig, value: str | Path) -> LoadedConfig:
    """Return an effective config with a plan-time variant-set override.

    The source config is not rewritten.  The override participates in the
    normalized config hash, so a state created for one set cannot resume under
    another set.
    """
    raw = str(value).replace("\\", "/")
    # Resolve now for a clear CLI error, while preserving the operator-provided
    # relative path in plan.json when possible.
    loaded.resolve_asset(raw)
    campaign = loaded.config.campaign.model_copy(update={"variants_file": raw})
    config = loaded.config.model_copy(update={"campaign": campaign})
    return LoadedConfig(
        config=config,
        source=loaded.source,
        base_dir=loaded.base_dir,
        sha256=config_sha256(config),
    )


def load_agent_config(path: str | Path, *, profile: str | None = None) -> LoadedAgentConfig:
    """Load one agent config.

    A file may describe a single executor (flat ``AgentConfig``) or several models
    under ``profiles:``.  In the multi-model form the top-level fields are shared
    defaults, each profile supplies ``model`` plus optional ``overrides``, and
    ``{model}`` inside ``argv`` is replaced with that profile's model id.  The
    selected profile participates in the returned digest, so two models from one
    file cannot be confused in a run record.
    """
    from .env import load_local_env

    load_local_env()
    source = _resolve(path)
    raw = _load_yaml(source)
    available: tuple[str, ...] = ()
    selected: str | None = None

    if "profiles" in raw:
        profiles_raw = raw.pop("profiles")
        if not isinstance(profiles_raw, dict) or not profiles_raw:
            raise ConfigError(
                "an agent config with profiles must declare at least one",
                details={"path": str(source)},
            )
        parsed: dict[str, AgentProfileConfig] = {}
        for name, entry in profiles_raw.items():
            try:
                parsed[str(name)] = AgentProfileConfig.model_validate(entry)
            except Exception as exc:
                raise ConfigError(
                    "invalid agent profile",
                    details={"path": str(source), "profile": str(name), "error": str(exc)},
                ) from exc
        available = tuple(sorted(parsed))
        default_name = raw.pop("default_profile", None) or available[0]
        selected = profile or str(default_name)
        if selected not in parsed:
            raise ConfigError(
                "unknown agent profile",
                details={
                    "path": str(source),
                    "requested": selected,
                    "available": list(available),
                },
            )
        entry = parsed[selected]
        payload: dict[str, Any] = dict(raw)
        payload.update(entry.overrides)
        argv = [str(item) for item in payload.get("argv") or []]
        if "{model}" in " ".join(argv):
            argv = [item.replace("{model}", entry.model) for item in argv]
        payload["argv"] = argv
        if entry.model_label:
            payload["model_label"] = entry.model_label
        elif not payload.get("model_label"):
            payload["model_label"] = entry.model
        if entry.requires_env:
            payload["requires_env"] = list(entry.requires_env)
    else:
        payload = raw

    try:
        agent = AgentConfig.model_validate(payload)
    except Exception as exc:
        raise ConfigError(
            f"invalid agent configuration: {exc}",
            details={"path": str(source), "profile": selected, "validation": str(exc)},
        ) from exc
    child_env: dict[str, str] = {}
    external_hashes: dict[str, str] = {}
    if agent.framework_config_file:
        raw_config = Path(agent.framework_config_file).expanduser()
        candidates = (
            [raw_config]
            if raw_config.is_absolute()
            else [source.parent / raw_config, project_root() / raw_config, Path.cwd() / raw_config]
        )
        framework_config = next(
            (item.resolve() for item in candidates if item.is_file()), None
        )
        if framework_config is None:
            raise ConfigError(
                "agent framework configuration file is missing",
                details={
                    "value": agent.framework_config_file,
                    "searched": [str(item) for item in candidates],
                },
            )
        child_env["OPENCODE_CONFIG"] = str(framework_config)
        external_hashes[f"framework_config:{framework_config.name}"] = sha256_file(
            framework_config
        )
    effective_sha = sha256_text(
        canonical_json(
            {
                "config": agent.model_dump(mode="json"),
                "profile": selected,
                "external_file_sha256": external_hashes,
            }
        )
    )
    return LoadedAgentConfig(
        config=agent,
        source=source,
        base_dir=source.parent,
        sha256=effective_sha,
        profile=selected,
        profiles=available,
        child_env=child_env,
        external_file_sha256=external_hashes,
    )


__all__ = [
    "AgentConfig",
    "AgentProfileConfig",
    "AppConfig",
    "ArchiveConfig",
    "ArchiveProviderConfig",
    "CampaignConfig",
    "EgressConfig",
    "ExtractionLimitsConfig",
    "GenerationBudgetConfig",
    "IsolationConfig",
    "LoadedAgentConfig",
    "LoadedConfig",
    "OutputContractConfig",
    "TierProfileConfig",
    "VariantEditConfig",
    "VariantSpecConfig",
    "VerifierConfig",
    "config_sha256",
    "load_agent_config",
    "load_config",
    "with_variant_set",
]
