package coverage

// Explain keeps stable machine-readable reason codes alongside readable text.
func Explain(reason string) string {
	switch reason {
	case "":
		return ""
	case "invalid_purl":
		return "The package URL is invalid."
	case "maven_without_group":
		return "Maven matching requires both a group and artifact name."
	case "qualified_language_purl":
		return "The language package URL has qualifiers or a subpath that this importer cannot preserve safely."
	case "os_architecture_scope_not_supported":
		return "The OS package is limited to an architecture; this importer cannot preserve that scope."
	case "os_purl_without_distro":
		return "The OS package URL does not identify a distribution release."
	case "unsupported_os_release":
		return "The distribution release cannot be mapped to a supported Trivy bucket."
	case "unsupported_purl_type":
		return "This package URL type or distribution is not supported by the importer."
	case "cpe_without_package_identity":
		return "A CPE identifies the product, but does not provide the package identity needed for Trivy matching."
	case "no_supported_package_identity":
		return "The source does not provide a supported package URL or an explicit package ecosystem and name."
	case "unsupported_version":
		return "The explicit package version cannot be translated safely."
	case "version_scheme_mismatch":
		return "The version range ecosystem differs from the package ecosystem."
	case "unknown_version":
		return "No usable affected version or version range is available."
	case "affected_versions_unspecified":
		return "NCSC marks the identified package and release affected but does not specify which versions; this is an uncertain candidate, not a precise version match."
	case "os_scope_not_supported":
		return "The OS package URL has a qualifier or subpath that stock Trivy cannot enforce."
	case "os_package_identity_conflict":
		return "The Alpine source-package name in the package URL conflicts with the product tree."
	case "unsupported_version_range":
		return "The affected version range contains syntax or versions the importer cannot parse."
	case "invalid_version_range_order":
		return "The version range bounds are not in increasing order."
	case "invalid_version_range_sequence":
		return "The version range comparator sequence is invalid."
	case "trivy_cannot_parse_version_constraint":
		return "Trivy's version parser cannot read the translated constraint."
	case "os_affected_range_not_supported_by_stock_trivy":
		return "Stock Trivy's OS advisory format cannot represent this affected range; an explicit first fix, upper bound, or all-version range is required."
	case "os_affected_range_conflict":
		return "The OS version observations cannot be combined into one supported Trivy advisory without changing their affected version scope."
	case "missing_product_reference":
		return "The vulnerability refers to a product ID absent from the source product tree."
	case "missing_database_advisory":
		return "The current importer can map this product, but the matching advisory is absent from this build; rebuild or audit the database."
	case "conversion_policy_unavailable":
		return "This legacy build did not record its conversion policy; the stored advisory inventory is authoritative, but its original decision rule is unavailable."
	case "first_fixed_non_os":
		return "The importer only uses first_fixed observations for OS packages; language advisories require known_affected versions."
	case "status_not_used_for_matching":
		return "This source status does not create an affected-package advisory; only known_affected and OS first_fixed are used."
	default:
		return "No description is available for this reason code."
	}
}
