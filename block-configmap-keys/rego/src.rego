package k8sazureblockconfigmapkeys

violation[{"msg": msg}] {
  input.review.kind.kind == "ConfigMap"
  input.review.kind.group == ""
  restrictedKeys := {keys | keys := input.parameters.restrictedKeys[_]}
  config := {config | config := input.review.object.data}
  any_key_is_restricted_key(config, restrictedKeys)
  msg := sprintf("ConfigMaps not allowed to have restricted keys: %v", [restrictedKeys])
}

any_key_is_restricted_key(config, restrictedKeys) {
    some key
    val := config[key]
    is_restricted_key(key, restrictedKeys)
}

is_restricted_key(key, restrictedKeys) {
    some i
    restrictedKeys[i]
    string_contains(key, restrictedKeys[i])
}

string_contains(key, subkey) {
  indexof(lower(key),lower(subkey)) != -1
}


