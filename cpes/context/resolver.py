"""Cross-channel context re-association (the CPES resolver).

Additive to the descriptive C7 context. Where ``ContextBuilder`` derives factual
per-lineage context, the resolver performs the *load-bearing* step: within one
detection window it re-associates an elevated **outcome** with the **mechanism
evidence** that explains it, bridging the operating-system re-parenting that
places actor, mechanism, and outcome in different subtrees/channels.

It reads only existing ``ContextEvent`` fields (image_path, integrity_level,
registry_object, command_line, occurred_at, privilege_identity) and treats the
supplied ``EventGroup`` (C8 windowing) as the temporal scope of association, so
no time threshold is embedded here. All discriminators (auto-elevating images,
hijack-registry tokens, system-path tokens, integrity ordering) are caller
supplied, consistent with the rest of the package; no evaluative weight is
assigned here (weights remain corpus-derived in M8 and applied additively in C9).

Scope of this module: all four mechanism re-associations. UAC (auto-elevating
LOLBin re-associated with the hijack registry write) and service (SYSTEM binary
run from a dropped location) use existing ``ContextEvent`` fields. Named-pipe
token impersonation (EID 17/18) and remote-thread injection (EID 8) are supplied
as optional cross-channel evidence to ``resolve`` (``PipeEvidence`` /
``RemoteThreadEvidence``), so they are handled **without** modifying the frozen
``ContextEvent`` model. Wiring these evidence streams through the windowing
pipeline end-to-end is a separate integration step.
"""

from __future__ import annotations

from dataclasses import dataclass

from cpes.context.models import PipeEvidence, RemoteThreadEvidence, ServiceInstallEvidence
from cpes.windowing.models import EventGroup

__all__ = ["ResolvedContext", "ContextResolver", "PipeEvidence", "RemoteThreadEvidence", "ServiceInstallEvidence"]


@dataclass(frozen=True)
class ResolvedContext:
    """One re-associated escalation: an anchored outcome plus its explanation.

    ``resolution_path`` records the concrete links used to associate the anchor
    with its evidence, so every association is auditable (the interpretability
    story, and the concrete mechanism for the novelty claim).
    """

    anchor_process_guid: str
    anchor_kind: str
    actor_process_guid: str | None
    mediator: str | None
    privilege_level: str | None
    evidence_event_ids: tuple[str, ...]
    resolution_path: tuple[str, ...]


def _basename(path: str | None) -> str:
    return (path or "").replace("/", "\\").split("\\")[-1].lower()


class ContextResolver:
    """Re-associate elevated outcomes to their mechanism evidence in a window."""

    def __init__(
        self,
        integrity_order: tuple[str, ...],
        auto_elevating_images: tuple[str, ...],
        hijack_registry_tokens: tuple[str, ...],
        *,
        elevated_levels: tuple[str, ...] = ("high", "system"),
        system_path_tokens: tuple[str, ...] = ("\\windows\\", "\\program files"),
        service_registry_tokens: tuple[str, ...] = ("\\services\\",),
        interactive_shell_images: tuple[str, ...] = ("cmd.exe", "powershell.exe", "pwsh.exe"),
        validly_signed_process_guids: frozenset[str] = frozenset(),
        uac_requires_hijack_write: bool = True,
        service_parent_images: tuple[str, ...] = (),
        require_service_install: bool = False,
        service_image_tokens: tuple[str, ...] = (),
        injection_images: tuple[str, ...] = (),
        remote_thread_source_images: tuple[str, ...] | None = None,
        token_first_creator_only: bool = False,
    ) -> None:
        if not integrity_order or len(set(integrity_order)) != len(integrity_order):
            raise ValueError("integrity_order must be a nonempty tuple of unique levels.")
        if not auto_elevating_images:
            raise ValueError("at least one auto-elevating image is required.")
        if not hijack_registry_tokens:
            raise ValueError("at least one hijack registry token is required.")
        if not elevated_levels:
            raise ValueError("at least one elevated level is required.")
        self._rank = {level.lower(): index for index, level in enumerate(integrity_order)}
        self._auto_images = frozenset(image.lower() for image in auto_elevating_images)
        self._hijack = tuple(token.lower() for token in hijack_registry_tokens)
        self._elevated = frozenset(level.lower() for level in elevated_levels)
        self._system_paths = tuple(token.lower() for token in system_path_tokens)
        self._service_reg = tuple(token.lower() for token in service_registry_tokens)
        self._shell_images = frozenset(image.lower() for image in interactive_shell_images)
        # Processes whose own image the telemetry recorded as validly signed
        # (cpes.context.signatures). Empty: the service test is location-only.
        self._signed = frozenset(validly_signed_process_guids)
        # Opt-in variants (docs/design/package-v3-and-vm2.md). Defaults keep the
        # behaviour every recorded result was produced with.
        # Structural: the service anchor's parent must be one of these images (B1)
        # and/or a service-install record must name its executable (B2).
        self._uac_needs_write = uac_requires_hijack_write
        self._service_parents = frozenset(image.lower() for image in service_parent_images)
        self._needs_install = require_service_install
        # NAME RULES (research-v3 replication): image-name matches, not mechanisms.
        self._service_name_tokens = tuple(token.lower() for token in service_image_tokens)
        self._injection_images = frozenset(image.lower() for image in injection_images)
        self._thread_sources = None if remote_thread_source_images is None else frozenset(i.lower() for i in remote_thread_source_images)
        self._first_creator_only = token_first_creator_only

    def _hijack_writes(self, events):
        return tuple(
            event
            for event in events
            if event.registry_object is not None
            and any(token in event.registry_object.lower() for token in self._hijack)
        )

    def _service_writes(self, events):
        return tuple(
            event
            for event in events
            if event.registry_object is not None
            and any(token in event.registry_object.lower() for token in self._service_reg)
        )

    def _is_system_path(self, image_path: str | None) -> bool:
        lowered = (image_path or "").lower()
        return any(token in lowered for token in self._system_paths)

    def resolve(
        self,
        event_group: EventGroup,
        *,
        pipe_evidence: tuple["PipeEvidence", ...] = (),
        remote_thread_evidence: tuple["RemoteThreadEvidence", ...] = (),
        service_install_evidence: tuple["ServiceInstallEvidence", ...] = (),
    ) -> tuple[ResolvedContext, ...]:
        """Emit one ResolvedContext per re-associated escalation in the window.

        ``pipe_evidence`` and ``remote_thread_evidence`` are optional cross-channel
        observations (EID 17/18 and EID 8) supplied alongside the window; when
        present they enable token-impersonation and injection re-association
        without changing the frozen ``ContextEvent`` model.
        """

        events = event_group.events
        hijack_writes = self._hijack_writes(events)
        service_writes = self._service_writes(events)
        resolved: list[ResolvedContext] = []

        for event in events:
            image = _basename(event.image_path)
            integrity = (event.integrity_level or "").lower()

            # UAC bypass: an auto-elevating LOLBin reached an elevated level AND a
            # UAC-hijack registry write is present in the same window. Re-association
            # over channels (process-create <- registry) is what makes this a
            # mechanism signal rather than an image IOC.
            if image in self._auto_images and integrity in self._elevated and (hijack_writes or not self._uac_needs_write):
                write = hijack_writes[0] if hijack_writes else None
                resolved.append(
                    ResolvedContext(
                        anchor_process_guid=event.process_guid,
                        anchor_kind="autoelevation_lolbin",
                        actor_process_guid=write.process_guid if write else None,
                        mediator="appinfo_consent",
                        privilege_level=event.integrity_level,
                        evidence_event_ids=(event.event_id, write.event_id) if write else (event.event_id,),
                        resolution_path=(
                            f"auto-elevating '{image}' at '{integrity}' re-associated "
                            f"with hijack registry write '{write.registry_object}' "
                            f"by actor {write.process_guid}"
                            if write else f"auto-elevating '{image}' at '{integrity}' (no hijack write required)",
                        ),
                    )
                )

            # Service creation: a SYSTEM-integrity binary run from a location outside
            # the system directories (a dropped binary), corroborated by a service
            # registry write when present. Structural — no image-name allow/deny list.
            # A process whose own image was recorded validly signed is skipped
            # when the caller supplies that set (S1; empty by default).
            structural = bool(
                integrity == "system"
                and event.image_path
                and image != "svchost.exe"
                and not self._is_system_path(event.image_path)
                and event.process_guid not in self._signed
                and (not self._service_parents or _basename(event.parent_image_path) in self._service_parents)
            )
            install = None
            if structural and self._needs_install:
                install = next((i for i in service_install_evidence if i.image_basename == image and i.occurred_at <= event.occurred_at), None)
                structural = install is not None
            # Name rule (research-v3 only): the image name contains a listed token.
            named = event.integrity_level is not None and any(token in image for token in self._service_name_tokens)
            if structural or named:
                evidence = [event.event_id]
                path = [f"SYSTEM binary '{image}' run from outside system directories" if structural else f"NAME RULE: image '{image}' matches a listed service token"]
                if self._service_parents and structural:
                    path.append(f"parent '{_basename(event.parent_image_path)}'")
                if install is not None:
                    evidence.append(install.event_id)
                    path.append(f"service-install record for '{install.image_basename}'")
                if service_writes:
                    evidence.append(service_writes[0].event_id)
                    path.append(
                        f"corroborating service registry write "
                        f"'{service_writes[0].registry_object}'"
                    )
                resolved.append(
                    ResolvedContext(
                        anchor_process_guid=event.process_guid,
                        anchor_kind="service_dropped_binary",
                        actor_process_guid=None,
                        mediator="scm",
                        privilege_level=event.integrity_level,
                        evidence_event_ids=tuple(evidence),
                        resolution_path=tuple(path),
                    )
                )

        # Token impersonation: a pipe created by a non-SYSTEM user and connected by
        # a SYSTEM interactive shell. Re-association across the pipe channel (create
        # <- connect) is what distinguishes impersonation from ordinary service IPC.
        creators_by_pipe: dict[str, PipeEvidence] = {}
        if self._first_creator_only:
            # research-v3: the first creator of each pipe, which must not be SYSTEM.
            first: dict[str, PipeEvidence] = {}
            for pipe in pipe_evidence:
                if pipe.action == "create":
                    first.setdefault(pipe.pipe_name, pipe)
            creators_by_pipe = {name: pipe for name, pipe in first.items() if not pipe.user_is_system}
        else:
            for pipe in pipe_evidence:
                if pipe.action == "create" and not pipe.user_is_system:
                    creators_by_pipe.setdefault(pipe.pipe_name, pipe)
        for pipe in pipe_evidence:
            if (
                pipe.action == "connect"
                and pipe.user_is_system
                and pipe.image_basename.lower() in self._shell_images
                and pipe.pipe_name in creators_by_pipe
            ):
                creator = creators_by_pipe[pipe.pipe_name]
                resolved.append(
                    ResolvedContext(
                        anchor_process_guid=pipe.process_guid,
                        anchor_kind="token_impersonation",
                        actor_process_guid=creator.process_guid,
                        mediator="named_pipe_impersonation",
                        privilege_level="System",
                        evidence_event_ids=(creator.event_id, pipe.event_id),
                        resolution_path=(
                            f"user-created pipe '{pipe.pipe_name}' (actor {creator.process_guid}) "
                            f"connected by SYSTEM shell '{pipe.image_basename}' -> impersonation",
                        ),
                    )
                )

        # Injection: a remote-thread creation re-associates injector -> victim.
        injectors: set[str] = set()
        for thread in remote_thread_evidence:
            if self._thread_sources is not None and thread.source_image_basename not in self._thread_sources:
                continue
            injectors.add(thread.source_process_guid)
            resolved.append(
                ResolvedContext(
                    anchor_process_guid=thread.source_process_guid,
                    anchor_kind="remote_thread_injection",
                    actor_process_guid=thread.source_process_guid,
                    mediator="remote_thread",
                    privilege_level=None,
                    evidence_event_ids=(thread.event_id,),
                    resolution_path=(
                        f"remote thread from '{thread.source_image_basename}' "
                        f"({thread.source_process_guid}) into target {thread.target_process_guid}",
                    ),
                )
            )
        # Name rule (research-v3 only): a process created from a listed injector image.
        for event in events:
            if event.integrity_level is not None and event.process_guid not in injectors and _basename(event.image_path) in self._injection_images:
                injectors.add(event.process_guid)
                resolved.append(
                    ResolvedContext(
                        anchor_process_guid=event.process_guid,
                        anchor_kind="remote_thread_injection",
                        actor_process_guid=event.process_guid,
                        mediator="image_name_rule",
                        privilege_level=event.integrity_level,
                        evidence_event_ids=(event.event_id,),
                        resolution_path=(f"NAME RULE: process image '{_basename(event.image_path)}' is a listed injector",),
                    )
                )

        return tuple(resolved)
