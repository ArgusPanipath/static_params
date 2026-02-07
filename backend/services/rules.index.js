/**
 * Static Security Rules Export
 * Aggregates all 32 static analysis rules for CERBERUS integration
 */

const rule01_entropy = require("./rule01_entropy");
const rule02_dangerous_api = require("./rule02_dangerous_api");
const rule03_code_diff = require("./rule03_code_diff");
const rule04_behavioral_sandbox = require("./rule04_sandbox");
const rule05_network_destinations = require("./rule05_network_destinations");
const rule06_filesystem_access = require("./rule06_filesystem_access");
const rule07_install_scripts = require("./rule07_install_scripts");
const rule08_dependency_confusion = require("./rule08_dependency_confusion");
const rule09_version_anomaly = require("./rule09_version_anomaly");
const rule10_readme_deception = require("./rule10_readme_deception");
const rule11_binary_detection = require("./rule11_binary_detection");
const rule12_crypto_miner = require("./rule12_crypto_miner");
const rule13_time_bomb = require("./rule13_time_bomb");
const rule14_environment_evasion = require("./rule14_environment_evasion");
const rule15_unicode_obfuscation = require("./rule15_unicode_obfuscation");
const rule16_dynamic_import = require("./rule16_dynamic_import");
const rule17_prototype_pollution = require("./rule17_prototype_pollution");
const rule18_wasm_binary = require("./rule18_wasm_detection");
const rule19_regex_complexity = require("./rule19_regex_complexity");
const rule20_native_addon = require("./rule20_native_addons");
const rule21_size_anomaly = require("./rule21_size_anomaly");
const rule22_conditional_deps = require("./rule22_conditional_deps");
const rule23_typosquat = require("./rule23_typosquatting");
const rule24_abandoned = require("./rule24_resurrection");
const rule25_minified = require("./rule25_minified_patches");
const rule26_reflective = require("./rule26_reflective_loading");
const rule27_stream_redirect = require("./rule27_socket_redirection");
const rule28_metadata_mismatch = require("./rule28_metadata_mismatch");
const rule29_sensitive_strings = require("./rule29_sensitive_keywords");
const rule30_license_anomaly = require("./rule30_license_anomaly");
const rule31_deadmans_switch = require("./rule31_dead_mans_switch");
const rule32_browser_api_hijack = require("./rule32_browser_hijacking");

// Export all rules as array
module.exports = [
  rule01_entropy,
  rule02_dangerous_api,
  rule03_code_diff,
  rule04_behavioral_sandbox,
  rule05_network_destinations,
  rule06_filesystem_access,
  rule07_install_scripts,
  rule08_dependency_confusion,
  rule09_version_anomaly,
  rule10_readme_deception,
  rule11_binary_detection,
  rule12_crypto_miner,
  rule13_time_bomb,
  rule14_environment_evasion,
  rule15_unicode_obfuscation,
  rule16_dynamic_import,
  rule17_prototype_pollution,
  rule18_wasm_binary,
  rule19_regex_complexity,
  rule20_native_addon,
  rule21_size_anomaly,
  rule22_conditional_deps,
  rule23_typosquat,
  rule24_abandoned,
  rule25_minified,
  rule26_reflective,
  rule27_stream_redirect,
  rule28_metadata_mismatch,
  rule29_sensitive_strings,
  rule30_license_anomaly,
  rule31_deadmans_switch,
  rule32_browser_api_hijack
];
