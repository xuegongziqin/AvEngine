#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rule_dir="${repo_root}/yara"
external_var_rule_list="${rule_dir}/external-variable-rules.txt"
build_dir="$(mktemp -d)"
trap 'rm -rf "${build_dir}"' EXIT

yarac_args=(
  -w
  -d filename=placeholder.bin
  -d filepath=/tmp/placeholder.bin
  -d extension=bin
  -d "filetype=ASCII text"
  -d filemode=0
  -d md5=00000000000000000000000000000000
  -d id=1
  -d owner=root
  -d group=root
  -d unpack_parent=
  -d unpack_source=
)

if [ ! -f "${external_var_rule_list}" ]; then
  echo "External-variable rule list not found: ${external_var_rule_list}" >&2
  exit 1
fi

mapfile -t external_var_rules < <(grep -E -v '^\s*(#|$)' "${external_var_rule_list}")
rules=("${rule_dir}"/*.yar "${rule_dir}"/*.yara)

if [ "${#rules[@]}" -eq 0 ]; then
  echo "No YARA rules found in ${rule_dir}" >&2
  exit 1
fi

is_external_var_rule() {
  local rule_name
  local allowed_rule

  rule_name="$(basename "$1")"

  for allowed_rule in "${external_var_rules[@]}"; do
    if [ "${rule_name}" = "${allowed_rule}" ]; then
      return 0
    fi
  done

  return 1
}

for rule_name in "${external_var_rules[@]}"; do
  if [ ! -f "${rule_dir}/${rule_name}" ]; then
    echo "Configured external-variable rule not found: ${rule_dir}/${rule_name}" >&2
    exit 1
  fi
done

strict_count=0
external_var_count=0
failed=0
compiler_log="$(mktemp)"
trap 'rm -rf "${build_dir}" "${compiler_log}"' EXIT

for rule in "${rules[@]}"; do
  if is_external_var_rule "${rule}"; then
    external_var_count=$((external_var_count + 1))
  else
    strict_count=$((strict_count + 1))
  fi
done

echo "Validating ${#rules[@]} YARA rule files (${strict_count} strict, ${external_var_count} with external variables)"

for rule in "${rules[@]}"; do
  if is_external_var_rule "${rule}"; then
    if ! yarac "${yarac_args[@]}" "${rule}" "${build_dir}/$(basename "${rule}").compiled" >"${compiler_log}" 2>&1; then
      echo "External-variable syntax check failed: ${rule}" >&2
      cat "${compiler_log}" >&2
      failed=1
    fi
  else
    if ! yarac -w "${rule}" "${build_dir}/$(basename "${rule}").compiled" >"${compiler_log}" 2>&1; then
      echo "Strict syntax check failed: ${rule}" >&2
      cat "${compiler_log}" >&2
      failed=1
    fi
  fi
done

if [ "${failed}" -ne 0 ]; then
  exit 1
fi

echo "YARA syntax validation passed"
