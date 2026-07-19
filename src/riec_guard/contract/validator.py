from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from datetime import datetime

from riec_guard.contract.canonicalize import (
    ContractCanonicalizationError,
    canonicalize_audit_contract,
    canonicalize_confirmation_fields,
    compute_contract_hash,
    normalize_unit,
)
from riec_guard.contract.models import (
    AssumptionSource,
    AuditContract,
    ColumnDataType,
    CompilerMode,
    ConfirmedBy,
    ConfirmationStatus,
    ContractRuntimeContext,
    ContractTransitionResult,
    ContractValidationCode,
    ContractValidationIssue,
    ContractValidationReport,
    ConversionMethod,
    DatasetProfile,
    IssueSeverity,
    OrderingStatus,
    PolicySourceKind,
    PrivacyClassification,
    QuantitySemantics,
    SourceMode,
    StorageMode,
)

DECISION_CRITICAL_CONFIRMATION_FIELDS = (
    "column_mapping.quantity.column",
    "column_mapping.deployment_group.column",
    "measurement.quantity_semantics",
    "measurement.unit",
    "grouping.deployment_group_columns",
    "ordering.status",
    "policy.nominal_quantity",
    "policy.lower_limit",
    "policy.alpha",
    "policy.minimum_actionable_shift",
    "policy.maximum_screening_shift",
    "policy.protocol_spread_tolerance",
    "riec.c",
    "privacy.classification",
)
_ORDERING_TIME_CONFIRMATION_FIELD = "ordering.time_column"
_VOLUME_UNITS = frozenset({"mL", "L", "uL"})
_MASS_UNITS = frozenset({"g", "kg", "mg"})
_SAFE_FIELD_PATH_PATTERN = re.compile(r"[A-Za-z0-9_.\[\]]{1,200}\Z")


def validate_audit_contract(
    contract: AuditContract | Mapping[str, object],
    dataset_profile: DatasetProfile,
    *,
    runtime_context: ContractRuntimeContext = ContractRuntimeContext.HOSTED_PUBLIC,
) -> ContractValidationReport:
    """Canonicalize and deterministically validate one contract against redacted profile facts."""

    incoming_id, incoming_status = _incoming_identity(contract)
    try:
        canonical = canonicalize_audit_contract(contract)
    except ContractCanonicalizationError as error:
        issue = _schema_issue(error.field_path)
        return _report(
            blocking=(issue,),
            warnings=(),
            confirmation_required=(),
            canonical_sha256=None,
            contract_id=None,
            analysis_permitted=False,
            g1_eligible=False,
        )

    identity = compute_contract_hash(canonical)
    blocking: list[ContractValidationIssue] = []
    warnings: list[ContractValidationIssue] = []
    profiles = {column.name: column for column in dataset_profile.column_profiles}

    if (
        canonical.source.dataset_id != dataset_profile.dataset_id
        or canonical.source.dataset_sha256 != dataset_profile.dataset_sha256
        or canonical.source.row_count != dataset_profile.row_count
        or canonical.source.column_count != len(dataset_profile.column_profiles)
    ):
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_SOURCE_PROFILE_MISMATCH,
                IssueSeverity.BLOCKING,
                "source",
                "Contract source identity or counts do not match the supplied dataset profile.",
            )
        )

    referenced_columns = (
        ("column_mapping.quantity.column", canonical.column_mapping.quantity.column),
        ("column_mapping.product.column", canonical.column_mapping.product.column),
        (
            "column_mapping.deployment_group.column",
            canonical.column_mapping.deployment_group.column,
        ),
        ("column_mapping.time.column", canonical.column_mapping.time.column),
        ("column_mapping.stream.column", canonical.column_mapping.stream.column),
        ("column_mapping.shift.column", canonical.column_mapping.shift.column),
        (
            "column_mapping.weight.column",
            canonical.column_mapping.weight.column if canonical.column_mapping.weight else None,
        ),
        (
            "column_mapping.density.column",
            canonical.column_mapping.density.column if canonical.column_mapping.density else None,
        ),
        (
            "column_mapping.tare.column",
            canonical.column_mapping.tare.column if canonical.column_mapping.tare else None,
        ),
    )
    for field_path, column_name in referenced_columns:
        if column_name is not None and column_name not in profiles:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND,
                    IssueSeverity.BLOCKING,
                    field_path,
                    "A mapped column does not exist exactly in the supplied dataset profile.",
                )
            )

    quantity_profile = profiles.get(canonical.column_mapping.quantity.column)
    if quantity_profile is not None and quantity_profile.dtype not in {
        ColumnDataType.INTEGER,
        ColumnDataType.NUMBER,
    }:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_QUANTITY_NOT_NUMERIC,
                IssueSeverity.BLOCKING,
                "column_mapping.quantity.column",
                "The mapped quantity column is not numeric in the dataset profile.",
            )
        )
    if not canonical.column_mapping.quantity.confirmed:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_QUANTITY_UNCONFIRMED,
                IssueSeverity.BLOCKING,
                "column_mapping.quantity.confirmed",
                "The decision-critical quantity mapping is not explicitly confirmed.",
            )
        )
    if not canonical.column_mapping.deployment_group.confirmed:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_GROUP_UNCONFIRMED,
                IssueSeverity.BLOCKING,
                "column_mapping.deployment_group.confirmed",
                "The deployment-group mapping is not explicitly confirmed.",
            )
        )

    if (
        canonical.column_mapping.deployment_group.column
        not in canonical.grouping.deployment_group_columns
    ):
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_GROUP_UNCONFIRMED,
                IssueSeverity.BLOCKING,
                "grouping.deployment_group_columns",
                "Grouping columns do not include the required deployment-group mapping.",
            )
        )

    group_profiles = []
    for index, column_name in enumerate(canonical.grouping.deployment_group_columns):
        profile = profiles.get(column_name)
        if profile is None:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND,
                    IssueSeverity.BLOCKING,
                    f"grouping.deployment_group_columns[{index}]",
                    "A deployment-group column does not exist in the dataset profile.",
                )
            )
            continue
        group_profiles.append(profile)
        if profile.missing_fraction > 0:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_GROUP_MISSING_VALUES,
                    IssueSeverity.BLOCKING,
                    f"grouping.deployment_group_columns[{index}]",
                    "A deployment-group column has missing values in the dataset profile.",
                )
            )
        if profile.unique_count <= 1:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_GROUP_CONSTANT,
                    IssueSeverity.BLOCKING,
                    f"grouping.deployment_group_columns[{index}]",
                    "A deployment-group column is constant in the dataset profile.",
                )
            )

    observed_group_count: int | None = None
    if len(canonical.grouping.deployment_group_columns) == 1 and group_profiles:
        observed_group_count = group_profiles[0].unique_count
        if observed_group_count < canonical.evidence_profile.min_groups_exploratory:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_INSUFFICIENT_GROUPS,
                    IssueSeverity.BLOCKING,
                    "grouping.deployment_group_columns",
                    "Group support is below the exploratory grouped-analysis minimum.",
                )
            )
        elif observed_group_count < canonical.evidence_profile.min_groups_action:
            warnings.append(
                _issue(
                    ContractValidationCode.CONTRACT_INSUFFICIENT_GROUPS,
                    IssueSeverity.WARNING,
                    "grouping.deployment_group_columns",
                    "Group support permits exploratory analysis only, not action support.",
                )
            )
    elif len(canonical.grouping.deployment_group_columns) > 1:
        warnings.append(
            _issue(
                ContractValidationCode.CONTRACT_INSUFFICIENT_GROUPS,
                IssueSeverity.WARNING,
                "grouping.deployment_group_columns",
                "Composite-group cardinality requires later normalized-data validation.",
            )
        )

    for index, column_name in enumerate(canonical.grouping.nested_context_columns or ()):
        if column_name not in profiles:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND,
                    IssueSeverity.BLOCKING,
                    f"grouping.nested_context_columns[{index}]",
                    "A nested-context column does not exist in the dataset profile.",
                )
            )

    conversion_valid = _validate_measurement_and_conversion(canonical, profiles, blocking)
    _validate_policy(canonical, blocking)
    _validate_evidence(canonical, dataset_profile, blocking, warnings)
    _validate_riec(canonical, observed_group_count, blocking)
    _validate_privacy(canonical, runtime_context, blocking)
    g1_candidate = _validate_ordering(canonical, profiles, blocking, warnings)

    if not conversion_valid:
        g1_candidate = False

    for index, unresolved in enumerate(canonical.unresolved_fields):
        if unresolved.severity is IssueSeverity.BLOCKING:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_UNRESOLVED_BLOCKING,
                    IssueSeverity.BLOCKING,
                    f"unresolved_fields[{index}]",
                    "A blocking unresolved contract field remains open.",
                )
            )
        else:
            warnings.append(
                _issue(
                    ContractValidationCode.CONTRACT_UNRESOLVED_WARNING,
                    IssueSeverity.WARNING,
                    f"unresolved_fields[{index}]",
                    "A nonblocking unresolved contract warning remains visible.",
                )
            )

    for index, assumption in enumerate(canonical.assumptions or ()):
        if not assumption.user_confirmed:
            message = (
                "A GPT-sourced assumption remains unconfirmed."
                if assumption.source is AssumptionSource.GPT_INFERENCE
                else "A contract assumption remains unconfirmed."
            )
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_ASSUMPTION_UNCONFIRMED,
                    IssueSeverity.BLOCKING,
                    f"assumptions[{index}]",
                    message,
                )
            )

    required_fields = _required_confirmation_fields(canonical)
    confirmed_fields = set(canonical.confirmation.confirmed_fields)
    confirmation_required = tuple(
        field for field in required_fields if field not in confirmed_fields
    )

    policy_source_confirmed = canonical.policy.policy_source.user_confirmed or (
        canonical.confirmation.status is ConfirmationStatus.CONFIRMED
        and canonical.confirmation.confirmed_by is ConfirmedBy.VERSIONED_BUILTIN
        and _is_versioned_builtin_policy_path(canonical)
    )
    if not policy_source_confirmed:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE,
                IssueSeverity.BLOCKING,
                "policy.policy_source.user_confirmed",
                "The policy source is not explicitly confirmed.",
            )
        )

    if canonical.confirmation.status is ConfirmationStatus.CONFIRMED:
        if confirmation_required:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE,
                    IssueSeverity.BLOCKING,
                    "confirmation.confirmed_fields",
                    "Decision-critical confirmation fields are incomplete.",
                )
            )
        if canonical.confirmation.confirmed_by not in {
            ConfirmedBy.USER,
            ConfirmedBy.VERSIONED_BUILTIN,
        } or not _is_rfc3339_timestamp(canonical.confirmation.confirmed_at):
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE,
                    IssueSeverity.BLOCKING,
                    "confirmation",
                    "Confirmed contracts require an explicit owner and valid timestamp.",
                )
            )
        if (
            canonical.confirmation.confirmed_by is ConfirmedBy.VERSIONED_BUILTIN
            and not _is_versioned_builtin_policy_path(canonical)
        ):
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE,
                    IssueSeverity.BLOCKING,
                    "confirmation.confirmed_by",
                    "Versioned built-in confirmation requires the versioned built-in path.",
                )
            )

    if (
        incoming_status is ConfirmationStatus.CONFIRMED
        and incoming_id is not None
        and incoming_id != identity.contract_id
    ):
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE,
                IssueSeverity.BLOCKING,
                "contract_id",
                "The incoming confirmed contract ID does not match recomputed identity.",
            )
        )

    ordered_blocking = _ordered_issues(blocking)
    ordered_warnings = _ordered_issues(warnings)
    valid = not ordered_blocking
    analysis_permitted = (
        valid
        and canonical.confirmation.status is ConfirmationStatus.CONFIRMED
        and not confirmation_required
        and canonical.contract_id == identity.contract_id
        and observed_group_count is not None
        and observed_group_count >= canonical.evidence_profile.min_groups_exploratory
    )
    return _report(
        blocking=ordered_blocking,
        warnings=ordered_warnings,
        confirmation_required=confirmation_required,
        canonical_sha256=identity.canonical_contract_sha256,
        contract_id=identity.contract_id,
        analysis_permitted=analysis_permitted,
        g1_eligible=analysis_permitted and g1_candidate,
    )


def analysis_is_permitted(report: ContractValidationReport) -> bool:
    """Return the validator's single deterministic Run Audit permission decision."""

    return report.analysis_permitted


def confirm_audit_contract(
    contract: AuditContract,
    dataset_profile: DatasetProfile,
    *,
    confirmed_fields: Collection[str],
    confirmed_by: ConfirmedBy,
    confirmed_at: str,
    runtime_context: ContractRuntimeContext = ContractRuntimeContext.HOSTED_PUBLIC,
) -> ContractTransitionResult:
    """Perform an explicit user/service-owned draft-to-confirmed transition."""

    incoming_contract_id = contract.contract_id
    canonical = canonicalize_audit_contract(contract)
    normalized_fields = _normalize_confirmed_fields(confirmed_fields)
    if canonical.confirmation.status is ConfirmationStatus.CONFIRMED:
        unchanged = (
            incoming_contract_id == canonical.contract_id
            and tuple(canonical.confirmation.confirmed_fields) == normalized_fields
            and canonical.confirmation.confirmed_by is confirmed_by
            and canonical.confirmation.confirmed_at == confirmed_at
        )
        report = validate_audit_contract(contract, dataset_profile, runtime_context=runtime_context)
        if unchanged:
            return ContractTransitionResult.model_validate(
                {
                    "contract": canonical,
                    "validation": report,
                    "transitioned": False,
                    "idempotent": True,
                }
            )
        return _invalid_transition(canonical, report)

    report = validate_audit_contract(canonical, dataset_profile, runtime_context=runtime_context)
    if canonical.confirmation.status is not ConfirmationStatus.DRAFT:
        return _invalid_transition(canonical, report)
    if confirmed_by not in {ConfirmedBy.USER, ConfirmedBy.VERSIONED_BUILTIN}:
        return _invalid_transition(canonical, report)
    if not _is_rfc3339_timestamp(confirmed_at):
        return _invalid_transition(canonical, report)
    if confirmed_by is ConfirmedBy.VERSIONED_BUILTIN and not _is_versioned_builtin_policy_path(
        canonical
    ):
        return _invalid_transition(canonical, report)

    required_fields = _required_confirmation_fields(canonical)
    if any(field not in normalized_fields for field in required_fields):
        return _incomplete_confirmation(canonical, report)
    pretransition_blocking = report.blocking_errors
    if confirmed_by is ConfirmedBy.VERSIONED_BUILTIN:
        pretransition_blocking = tuple(
            issue
            for issue in pretransition_blocking
            if not (
                issue.code is ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE
                and issue.field_path == "policy.policy_source.user_confirmed"
            )
        )
    if pretransition_blocking:
        return ContractTransitionResult.model_validate(
            {
                "contract": canonical,
                "validation": report,
                "transitioned": False,
                "idempotent": False,
            }
        )

    payload = canonical.to_canonical_dict()
    payload["confirmation"] = {
        "status": ConfirmationStatus.CONFIRMED,
        "confirmed_fields": normalized_fields,
        "confirmed_at": confirmed_at.strip(),
        "confirmed_by": confirmed_by,
    }
    confirmed = canonicalize_audit_contract(payload)
    confirmed_report = validate_audit_contract(
        confirmed, dataset_profile, runtime_context=runtime_context
    )
    if confirmed_report.blocking_errors:
        return ContractTransitionResult.model_validate(
            {
                "contract": canonical,
                "validation": confirmed_report,
                "transitioned": False,
                "idempotent": False,
            }
        )
    return ContractTransitionResult.model_validate(
        {
            "contract": confirmed,
            "validation": confirmed_report,
            "transitioned": True,
            "idempotent": False,
        }
    )


def reject_audit_contract(
    contract: AuditContract,
    dataset_profile: DatasetProfile,
    *,
    runtime_context: ContractRuntimeContext = ContractRuntimeContext.HOSTED_PUBLIC,
) -> ContractTransitionResult:
    """Perform the only supported rejection transition: draft to rejected."""

    canonical = canonicalize_audit_contract(contract)
    report = validate_audit_contract(canonical, dataset_profile, runtime_context=runtime_context)
    if canonical.confirmation.status is not ConfirmationStatus.DRAFT:
        return _invalid_transition(canonical, report)
    payload = canonical.to_canonical_dict()
    payload["confirmation"] = {
        "status": ConfirmationStatus.REJECTED,
        "confirmed_fields": tuple(canonical.confirmation.confirmed_fields),
        "confirmed_at": None,
        "confirmed_by": ConfirmedBy.NONE,
    }
    rejected = canonicalize_audit_contract(payload)
    rejected_report = validate_audit_contract(
        rejected, dataset_profile, runtime_context=runtime_context
    )
    return ContractTransitionResult.model_validate(
        {
            "contract": rejected,
            "validation": rejected_report,
            "transitioned": True,
            "idempotent": False,
        }
    )


def _validate_measurement_and_conversion(
    contract: AuditContract,
    profiles: Mapping[str, object],
    blocking: list[ContractValidationIssue],
) -> bool:
    unit = normalize_unit(contract.measurement.unit)
    if unit is None:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_UNIT_UNKNOWN,
                IssueSeverity.BLOCKING,
                "measurement.unit",
                "The declared unit is not in the frozen Fill Pack unit registry.",
            )
        )

    conversion = contract.measurement.conversion
    valid = True
    if conversion.required and conversion.method is ConversionMethod.NONE:
        valid = False
    if not conversion.required and conversion.method is not ConversionMethod.NONE:
        valid = False
    if conversion.method is ConversionMethod.NONE and conversion.fixed_density is not None:
        valid = False
    if conversion.method is ConversionMethod.FIXED_DENSITY:
        valid = conversion.required and conversion.fixed_density is not None
    elif conversion.method is ConversionMethod.ROW_DENSITY:
        density = contract.column_mapping.density
        density_profile = profiles.get(density.column) if density and density.column else None
        valid = (
            conversion.required
            and density_profile is not None
            and getattr(density_profile, "dtype", None)
            in {ColumnDataType.INTEGER, ColumnDataType.NUMBER}
        )
    elif conversion.method is ConversionMethod.GROSS_MINUS_TARE:
        weight = contract.column_mapping.weight
        tare = contract.column_mapping.tare
        weight_profile = profiles.get(weight.column) if weight and weight.column else None
        tare_profile = profiles.get(tare.column) if tare and tare.column else None
        valid = (
            conversion.required
            and getattr(weight_profile, "dtype", None)
            in {ColumnDataType.INTEGER, ColumnDataType.NUMBER}
            and getattr(tare_profile, "dtype", None)
            in {ColumnDataType.INTEGER, ColumnDataType.NUMBER}
        )
    elif conversion.method is ConversionMethod.CUSTOM:
        valid = conversion.required and bool(
            conversion.formula_note and conversion.formula_note.strip()
        )
    if not valid:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_CONVERSION_INVALID,
                IssueSeverity.BLOCKING,
                "measurement.conversion",
                "The declared conversion method and required inputs are inconsistent.",
            )
        )

    semantics = contract.measurement.quantity_semantics
    compatible = True
    if unit is not None:
        if semantics is QuantitySemantics.VOLUME:
            compatible = unit in _VOLUME_UNITS
        elif semantics in {
            QuantitySemantics.GROSS_WEIGHT,
            QuantitySemantics.NET_WEIGHT,
            QuantitySemantics.MASS,
        }:
            compatible = unit in _MASS_UNITS
        elif semantics is QuantitySemantics.NET_CONTENT:
            compatible = unit in _VOLUME_UNITS | _MASS_UNITS
        elif semantics is QuantitySemantics.OTHER:
            compatible = unit in _VOLUME_UNITS | _MASS_UNITS
        if not compatible and conversion.method not in {
            ConversionMethod.FIXED_DENSITY,
            ConversionMethod.ROW_DENSITY,
        }:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_UNIT_SEMANTICS_MISMATCH,
                    IssueSeverity.BLOCKING,
                    "measurement",
                    "Quantity semantics and final declared unit are incompatible.",
                )
            )
    return valid and (
        compatible
        or conversion.method
        in {
            ConversionMethod.FIXED_DENSITY,
            ConversionMethod.ROW_DENSITY,
        }
    )


def _validate_policy(contract: AuditContract, blocking: list[ContractValidationIssue]) -> None:
    policy = contract.policy
    if policy.lower_limit > policy.nominal_quantity:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_POLICY_ORDER_INVALID,
                IssueSeverity.BLOCKING,
                "policy.lower_limit",
                "The lower limit exceeds nominal quantity.",
            )
        )
    if policy.maximum_screening_shift < policy.minimum_actionable_shift:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_SHIFT_RANGE_INVALID,
                IssueSeverity.BLOCKING,
                "policy.maximum_screening_shift",
                "Maximum screening shift is below minimum actionable shift.",
            )
        )


def _validate_evidence(
    contract: AuditContract,
    profile: DatasetProfile,
    blocking: list[ContractValidationIssue],
    warnings: list[ContractValidationIssue],
) -> None:
    evidence = contract.evidence_profile
    if evidence.min_groups_action < evidence.min_groups_exploratory:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_EVIDENCE_PROFILE_INVALID,
                IssueSeverity.BLOCKING,
                "evidence_profile.min_groups_action",
                "Action group minimum is below the exploratory group minimum.",
            )
        )
    if profile.row_count < evidence.min_rows:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_EVIDENCE_PROFILE_INVALID,
                IssueSeverity.BLOCKING,
                "evidence_profile.min_rows",
                "Dataset rows are below the declared minimum.",
            )
        )
    if profile.row_count * contract.policy.alpha < evidence.min_expected_tail_count:
        warnings.append(
            _issue(
                ContractValidationCode.CONTRACT_EVIDENCE_PROFILE_INVALID,
                IssueSeverity.WARNING,
                "evidence_profile.min_expected_tail_count",
                "Expected tail support is below the declared action threshold.",
            )
        )


def _validate_riec(
    contract: AuditContract,
    observed_group_count: int | None,
    blocking: list[ContractValidationIssue],
) -> None:
    riec = contract.riec
    if (
        riec.baseline_candidate_id != "M0_intercept"
        or riec.risk_aggregation != "row_weighted_grouped_mse"
        or riec.splitter != "leave_one_deployment_group_out"
        or riec.c < 0
        or riec.near_tie_abs_tol < 0
        or riec.near_tie_rel_tol < 0
        or not riec.candidate_registry_id
        or observed_group_count is not None
        and observed_group_count > riec.max_exact_logo_groups
    ):
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_RIEC_SETTINGS_INVALID,
                IssueSeverity.BLOCKING,
                "riec",
                "RIEC settings violate the frozen candidate/risk/splitter/scale contract.",
            )
        )


def _validate_privacy(
    contract: AuditContract,
    runtime_context: ContractRuntimeContext,
    blocking: list[ContractValidationIssue],
) -> None:
    privacy = contract.privacy
    expected = {
        SourceMode.BUILTIN_SYNTHETIC: (
            PrivacyClassification.PUBLIC_SYNTHETIC,
            StorageMode.EPHEMERAL_PUBLIC_SESSION,
        ),
        SourceMode.UPLOADED_PUBLIC: (
            PrivacyClassification.PUBLIC_USER_UPLOAD,
            StorageMode.EPHEMERAL_PUBLIC_SESSION,
        ),
        SourceMode.LOCAL_PRIVATE: (
            PrivacyClassification.PRIVATE_INDUSTRIAL,
            StorageMode.LOCAL_PRIVATE_WORKSPACE,
        ),
    }[contract.source.mode]
    invalid = (
        privacy.classification is not expected[0]
        or privacy.storage_mode is not expected[1]
        or privacy.raw_rows_to_gpt is not False
        or privacy.direct_identifiers_to_gpt is not False
        or runtime_context is ContractRuntimeContext.HOSTED_PUBLIC
        and (
            privacy.classification is PrivacyClassification.PRIVATE_INDUSTRIAL
            or privacy.storage_mode is StorageMode.LOCAL_PRIVATE_WORKSPACE
        )
    )
    if invalid:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_PRIVACY_MODE_INVALID,
                IssueSeverity.BLOCKING,
                "privacy",
                "Source, storage, outbound flags, and runtime privacy mode are inconsistent.",
            )
        )


def _validate_ordering(
    contract: AuditContract,
    profiles: Mapping[str, object],
    blocking: list[ContractValidationIssue],
    warnings: list[ContractValidationIssue],
) -> bool:
    ordering = contract.ordering
    time_ref = contract.column_mapping.time
    stream_ref = contract.column_mapping.stream
    if ordering.status is OrderingStatus.CONFIRMED:
        if (
            ordering.time_column is None
            or not ordering.within_stream_order_confirmed
            or time_ref.column is None
            or time_ref.column != ordering.time_column
        ):
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT,
                    IssueSeverity.BLOCKING,
                    "ordering",
                    "Confirmed ordering has inconsistent time mapping or confirmation state.",
                )
            )
        time_profile = profiles.get(ordering.time_column) if ordering.time_column else None
        if (
            time_profile is not None
            and getattr(time_profile, "dtype", None) is not ColumnDataType.DATETIME
        ):
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT,
                    IssueSeverity.BLOCKING,
                    "ordering.time_column",
                    "Confirmed ordering requires a datetime profile column.",
                )
            )
        if not time_ref.confirmed:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_ORDER_UNCONFIRMED,
                    IssueSeverity.BLOCKING,
                    "column_mapping.time.confirmed",
                    "The confirmed ordering time mapping is not explicitly confirmed.",
                )
            )
        for index, column_name in enumerate(ordering.tie_break_columns or ()):
            if column_name not in profiles:
                blocking.append(
                    _issue(
                        ContractValidationCode.CONTRACT_COLUMN_NOT_FOUND,
                        IssueSeverity.BLOCKING,
                        f"ordering.tie_break_columns[{index}]",
                        "An ordering tie-break column does not exist in the dataset profile.",
                    )
                )
        stream_ready = (
            stream_ref.column is not None and stream_ref.column in profiles and stream_ref.confirmed
        )
        if not stream_ready:
            warnings.append(
                _issue(
                    ContractValidationCode.CONTRACT_ORDER_UNCONFIRMED,
                    IssueSeverity.WARNING,
                    "column_mapping.stream",
                    "G1 is ineligible until a stream mapping is present and confirmed.",
                )
            )
        return (
            ordering.time_column is not None
            and ordering.within_stream_order_confirmed
            and time_ref.column == ordering.time_column
            and time_ref.confirmed
            and getattr(time_profile, "dtype", None) is ColumnDataType.DATETIME
            and stream_ready
        )
    if ordering.status is OrderingStatus.UNAVAILABLE:
        if ordering.time_column is not None or ordering.within_stream_order_confirmed:
            blocking.append(
                _issue(
                    ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT,
                    IssueSeverity.BLOCKING,
                    "ordering",
                    "Unavailable ordering must not contain a confirmed time order.",
                )
            )
        warnings.append(
            _issue(
                ContractValidationCode.CONTRACT_ORDER_UNCONFIRMED,
                IssueSeverity.WARNING,
                "ordering.status",
                "Order is unavailable; G1 is ineligible while grouped RIEC may remain valid.",
            )
        )
        return False

    if ordering.within_stream_order_confirmed:
        blocking.append(
            _issue(
                ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT,
                IssueSeverity.BLOCKING,
                "ordering.within_stream_order_confirmed",
                "Ambiguous ordering cannot be marked confirmed within streams.",
            )
        )
    warnings.append(
        _issue(
            ContractValidationCode.CONTRACT_ORDER_UNCONFIRMED,
            IssueSeverity.WARNING,
            "ordering.status",
            "Order remains ambiguous; G1 is ineligible and ambiguity is preserved.",
        )
    )
    return False


def _required_confirmation_fields(contract: AuditContract) -> tuple[str, ...]:
    fields = list(DECISION_CRITICAL_CONFIRMATION_FIELDS)
    if contract.ordering.status is OrderingStatus.CONFIRMED:
        ordering_position = fields.index("ordering.status") + 1
        fields.insert(ordering_position, _ORDERING_TIME_CONFIRMATION_FIELD)
    return tuple(fields)


def _is_versioned_builtin_policy_path(contract: AuditContract) -> bool:
    return (
        contract.compiler is not None
        and contract.compiler.mode is CompilerMode.VERSIONED_BUILTIN
        and contract.policy.policy_source.kind is PolicySourceKind.BUILTIN_PROFILE
    )


def _normalize_confirmed_fields(fields: Collection[str]) -> tuple[str, ...]:
    return canonicalize_confirmation_fields(tuple(fields))


def _incoming_identity(
    contract: AuditContract | Mapping[str, object],
) -> tuple[str | None, ConfirmationStatus | None]:
    if isinstance(contract, AuditContract):
        return contract.contract_id, contract.confirmation.status
    contract_id = contract.get("contract_id")
    confirmation = contract.get("confirmation")
    raw_status = confirmation.get("status") if isinstance(confirmation, Mapping) else None
    try:
        status = ConfirmationStatus(raw_status) if isinstance(raw_status, str) else None
    except ValueError:
        status = None
    return contract_id if isinstance(contract_id, str) else None, status


def _schema_issue(field_path: str) -> ContractValidationIssue:
    safe_path = field_path if _SAFE_FIELD_PATH_PATTERN.fullmatch(field_path) else "root"
    code = ContractValidationCode.CONTRACT_SCHEMA_INVALID
    if safe_path.startswith("policy.alpha"):
        code = ContractValidationCode.CONTRACT_ALPHA_INVALID
    elif safe_path.startswith("policy.minimum_actionable_shift") or safe_path.startswith(
        "policy.maximum_screening_shift"
    ):
        code = ContractValidationCode.CONTRACT_SHIFT_RANGE_INVALID
    elif safe_path.startswith("policy"):
        code = ContractValidationCode.CONTRACT_POLICY_ORDER_INVALID
    elif safe_path.startswith("measurement.measurement_resolution"):
        code = ContractValidationCode.CONTRACT_RESOLUTION_INVALID
    elif safe_path.startswith("measurement.conversion"):
        code = ContractValidationCode.CONTRACT_CONVERSION_INVALID
    elif safe_path.startswith("evidence_profile"):
        code = ContractValidationCode.CONTRACT_EVIDENCE_PROFILE_INVALID
    elif safe_path.startswith("ordering"):
        code = ContractValidationCode.CONTRACT_ORDERING_INCONSISTENT
    elif safe_path.startswith("riec"):
        code = ContractValidationCode.CONTRACT_RIEC_SETTINGS_INVALID
    elif safe_path.startswith("privacy"):
        code = ContractValidationCode.CONTRACT_PRIVACY_MODE_INVALID
    elif safe_path.startswith("grouping.no_random_row_fallback"):
        code = ContractValidationCode.CONTRACT_GROUP_UNCONFIRMED
    elif safe_path.startswith("confirmation"):
        code = ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE
    return _issue(
        code,
        IssueSeverity.BLOCKING,
        safe_path,
        "The contract does not satisfy a required canonical shape or bounded value rule.",
    )


def _issue(
    code: ContractValidationCode,
    severity: IssueSeverity,
    field_path: str,
    message: str,
) -> ContractValidationIssue:
    return ContractValidationIssue.model_validate(
        {
            "code": code,
            "severity": severity,
            "field_path": field_path,
            "message": message,
            "recoverable": True,
            "user_action": "Correct or explicitly confirm the identified contract field.",
        }
    )


def _report(
    *,
    blocking: Collection[ContractValidationIssue],
    warnings: Collection[ContractValidationIssue],
    confirmation_required: Collection[str],
    canonical_sha256: str | None,
    contract_id: str | None,
    analysis_permitted: bool,
    g1_eligible: bool,
) -> ContractValidationReport:
    ordered_blocking = _ordered_issues(blocking)
    ordered_warnings = _ordered_issues(warnings)
    return ContractValidationReport.model_validate(
        {
            "valid": not ordered_blocking,
            "blocking_errors": ordered_blocking,
            "warnings": ordered_warnings,
            "confirmation_required": tuple(confirmation_required),
            "canonical_contract_sha256": canonical_sha256,
            "contract_id": contract_id,
            "analysis_permitted": analysis_permitted and not ordered_blocking,
            "g1_eligible": g1_eligible and analysis_permitted and not ordered_blocking,
        }
    )


def _ordered_issues(
    issues: Collection[ContractValidationIssue],
) -> tuple[ContractValidationIssue, ...]:
    unique = {
        (issue.code.value, issue.severity.value, issue.field_path, issue.message): issue
        for issue in issues
    }
    return tuple(unique[key] for key in sorted(unique))


def _invalid_transition(
    contract: AuditContract, report: ContractValidationReport
) -> ContractTransitionResult:
    issue = _issue(
        ContractValidationCode.CONTRACT_INVALID_TRANSITION,
        IssueSeverity.BLOCKING,
        "confirmation.status",
        "The requested confirmation-state transition is not permitted.",
    )
    updated = _report(
        blocking=(*report.blocking_errors, issue),
        warnings=report.warnings,
        confirmation_required=report.confirmation_required,
        canonical_sha256=report.canonical_contract_sha256,
        contract_id=report.contract_id,
        analysis_permitted=False,
        g1_eligible=False,
    )
    return ContractTransitionResult.model_validate(
        {
            "contract": contract,
            "validation": updated,
            "transitioned": False,
            "idempotent": False,
        }
    )


def _incomplete_confirmation(
    contract: AuditContract, report: ContractValidationReport
) -> ContractTransitionResult:
    issue = _issue(
        ContractValidationCode.CONTRACT_CONFIRMATION_INCOMPLETE,
        IssueSeverity.BLOCKING,
        "confirmation.confirmed_fields",
        "The explicit confirmation field set is incomplete.",
    )
    updated = _report(
        blocking=(*report.blocking_errors, issue),
        warnings=report.warnings,
        confirmation_required=report.confirmation_required,
        canonical_sha256=report.canonical_contract_sha256,
        contract_id=report.contract_id,
        analysis_permitted=False,
        g1_eligible=False,
    )
    return ContractTransitionResult.model_validate(
        {
            "contract": contract,
            "validation": updated,
            "transitioned": False,
            "idempotent": False,
        }
    )


def _is_rfc3339_timestamp(value: str | None) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip()
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError:
        return False
    return parsed.tzinfo is not None


__all__ = [
    "DECISION_CRITICAL_CONFIRMATION_FIELDS",
    "analysis_is_permitted",
    "confirm_audit_contract",
    "reject_audit_contract",
    "validate_audit_contract",
]
