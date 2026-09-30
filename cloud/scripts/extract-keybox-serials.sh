#!/data/data/com.termux/files/usr/bin/bash

set -euo pipefail

readonly PROGRAM_NAME="${0##*/}"
DETAILS=0
FEATURES=0
CHECK_ONLY=0
OUTPUT_PATH=""
TERMUX_PREFIX=""
TEMP_PARENT=""
WORK_DIR=""
declare -a INPUT_PATHS=()

usage() {
  cat <<'EOF'
Extract one leaf-certificate SerialNumber from every Key in Android keybox XML.

Usage:
  extract-keybox-serials.sh [--details] [-o OUTPUT] INPUT...
  extract-keybox-serials.sh --check

Inputs:
  A file is processed directly. A directory is searched recursively for
  *.xml and *.keybox files. Use - to read one keybox from standard input.

Options:
  --details       Output TSV with Keybox/Key indexes and declared counts.
  --features      Output TSV: serial_number, certificate_sha256,
                  issuer_spki_sha256, Keybox/Key indexes and source_file.
  --check         Verify the runtime, dependencies and temporary directory.
  -o, --output    Write to a new file instead of stdout; never overwrite.
  -h, --help      Show this help text.

Default output is one normalized serial number per <Key>, in source, Keybox and
Key order. Only the first certificate (the leaf) in that Key's chain is selected.
A file is rejected unless its declared Keybox/certificate counts match and every
Key has exactly one CertificateChain. Feature TSV includes a mandatory schema
header so the importer can reject missing, duplicate or partial Key results.
Feature mode also reads the next certificate to verify and hash the issuer SPKI.

Termux dependencies:
  pkg install bash coreutils findutils gawk openssl

For a root-only keybox, keep the script in the normal Termux environment:
  su -c 'cat /root/only/keybox.xml' | bash extract-keybox-serials.sh -
EOF
}

die() {
  printf '%s: %s\n' "$PROGRAM_NAME" "$*" >&2
  exit 1
}

warn() {
  printf '%s: warning: %s\n' "$PROGRAM_NAME" "$*" >&2
}

detect_termux_prefix() {
  local candidate
  for candidate in \
    "${PREFIX:-}" \
    "/data/data/com.termux/files/usr" \
    "/data/user/0/com.termux/files/usr"; do
    [[ -n $candidate && -d $candidate/bin ]] || continue
    if [[ -x $candidate/bin/bash ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

create_work_dir() {
  local candidate candidate_dir
  for candidate in \
    "${TMPDIR:-}" \
    "${TERMUX_PREFIX:+$TERMUX_PREFIX/tmp}" \
    "${PREFIX:+$PREFIX/tmp}" \
    "${HOME:+$HOME/.cache}" \
    "${HOME:-}" \
    "/tmp"; do
    [[ -n $candidate && -d $candidate && -w $candidate ]] || continue
    if candidate_dir=$(mktemp -d "$candidate/trustattestor-keybox.XXXXXX" 2>/dev/null); then
      TEMP_PARENT=$candidate
      WORK_DIR=$candidate_dir
      return 0
    fi
  done
  return 1
}

cleanup() {
  if [[ -n ${WORK_DIR:-} && -n ${TEMP_PARENT:-} && -d $WORK_DIR ]]; then
    case "$WORK_DIR" in
      "$TEMP_PARENT"/trustattestor-keybox.*)
        rm -rf -- "$WORK_DIR"
        ;;
    esac
  fi
}

while (($# > 0)); do
  case "$1" in
    --details)
      DETAILS=1
      shift
      ;;
    --features)
      FEATURES=1
      shift
      ;;
    --check)
      CHECK_ONLY=1
      shift
      ;;
    -o|--output)
      (($# >= 2)) || die "$1 requires a path"
      OUTPUT_PATH=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      INPUT_PATHS+=("$@")
      break
      ;;
    -)
      INPUT_PATHS+=("$1")
      shift
      ;;
    -*)
      die "unknown option: $1"
      ;;
    *)
      INPUT_PATHS+=("$1")
      shift
      ;;
  esac
done

TERMUX_PREFIX=$(detect_termux_prefix || true)
if [[ -n $TERMUX_PREFIX ]]; then
  PATH="$TERMUX_PREFIX/bin:$PATH"
  export PATH
fi

declare -a REQUIRED_COMMANDS=(awk cat find sort mktemp openssl mkdir mv rm)
declare -a MISSING_COMMANDS=()
for required_command in "${REQUIRED_COMMANDS[@]}"; do
  command -v "$required_command" >/dev/null 2>&1 || MISSING_COMMANDS+=("$required_command")
done
if ((${#MISSING_COMMANDS[@]} > 0)); then
  if [[ -n $TERMUX_PREFIX || -d /data/data/com.termux/files/usr ]]; then
    die "missing command(s): ${MISSING_COMMANDS[*]}. Run: pkg install bash coreutils findutils gawk openssl"
  fi
  die "missing required command(s): ${MISSING_COMMANDS[*]}"
fi

umask 077
create_work_dir || die "could not create a private temporary directory; set TMPDIR to one"
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if ((CHECK_ONLY == 1)); then
  printf 'Runtime OK\n'
  if [[ -n $TERMUX_PREFIX ]]; then
    printf 'Termux prefix: %s\n' "$TERMUX_PREFIX"
  else
    printf 'Termux prefix: not detected (generic Bash mode)\n'
  fi
  printf 'OpenSSL: %s\n' "$(command -v openssl)"
  printf 'Temporary directory: %s\n' "$TEMP_PARENT"
  exit 0
fi

((${#INPUT_PATHS[@]} > 0)) || die "no input file, directory or - was provided"
if [[ -n $OUTPUT_PATH && -e $OUTPUT_PATH ]]; then
  die "refusing to overwrite existing output: $OUTPUT_PATH"
fi

declare -a KEYBOX_FILES=()
declare -a KEYBOX_SOURCES=()
stdin_seen=0
input_index=0
for input_path in "${INPUT_PATHS[@]}"; do
  ((input_index += 1))
  if [[ $input_path == - ]]; then
    ((stdin_seen == 0)) || die "standard input may only be specified once"
    [[ -r /dev/stdin ]] || die "standard input is not readable"
    KEYBOX_FILES+=("/dev/stdin")
    KEYBOX_SOURCES+=("<stdin>")
    stdin_seen=1
  elif [[ -f $input_path ]]; then
    [[ -r $input_path ]] || die "input file is not readable: $input_path"
    KEYBOX_FILES+=("$input_path")
    KEYBOX_SOURCES+=("$input_path")
  elif [[ -d $input_path ]]; then
    [[ -r $input_path && -x $input_path ]] || die "input directory is not searchable: $input_path"
    candidate_list="$WORK_DIR/find-$input_index.list"
    if ! find "$input_path" -type f \( -iname '*.xml' -o -iname '*.keybox' \) -print0 >"$candidate_list"; then
      die "could not search input directory: $input_path"
    fi
    while IFS= read -r -d '' candidate; do
      if [[ -r $candidate ]]; then
        KEYBOX_FILES+=("$candidate")
        KEYBOX_SOURCES+=("$candidate")
      else
        warn "skipping unreadable keybox file: $candidate"
      fi
    done <"$candidate_list"
  else
    die "input does not exist or is not a regular file/directory: $input_path"
  fi
done

((${#KEYBOX_FILES[@]} > 0)) || die "no readable keybox files were found"

RESULTS_FILE="$WORK_DIR/results.tsv"
: >"$RESULTS_FILE"
failure_count=0
leaf_count=0

for ((file_index = 0; file_index < ${#KEYBOX_FILES[@]}; file_index += 1)); do
  keybox_file=${KEYBOX_FILES[$file_index]}
  keybox_source=${KEYBOX_SOURCES[$file_index]}
  if [[ $keybox_source == *$'\t'* || $keybox_source == *$'\n'* ]]; then
    die "input path contains a tab or newline and cannot be represented safely in TSV: $keybox_source"
  fi
  file_dir="$WORK_DIR/file-$((file_index + 1))"
  mkdir -p -- "$file_dir"
  manifest="$file_dir/manifest.tsv"

  if ! awk '{ line = $0; gsub(/>[[:space:]]*</, ">\n<", line); print line }' "$keybox_file" \
    | awk -v output_dir="$file_dir" '
    BEGIN {
      begin_marker = "-----BEGIN CERTIFICATE-----"
      end_marker = "-----END CERTIFICATE-----"
      declared_keyboxes = 0
      saw_declared_keyboxes = 0
      keybox_index = 0
      in_keybox = 0
      in_key = 0
      chain_index = 0
      capture = 0
      in_chain = 0
      fatal = 0
    }

    function fail_parse() {
      fatal = 1
      exit 2
    }

    function finish_chain() {
      if (!in_chain || capture || certificate_position < 1 || leaf_file == "") fail_parse()
      if (!saw_declared_certificates || declared_certificates != certificate_position) fail_parse()
      key_chain_index = chain_index
      key_leaf_file = leaf_file
      key_issuer_file = issuer_file
      in_chain = 0
    }

    function finish_key() {
      if (!in_key || in_chain || capture || key_chain_count != 1 || key_leaf_file == "") fail_parse()
      result_chain_index[key_index] = key_chain_index
      result_leaf_file[key_index] = key_leaf_file
      result_issuer_file[key_index] = key_issuer_file
      in_key = 0
    }

    function finish_keybox(emit_index) {
      if (!in_keybox || in_key || in_chain || capture || key_count < 1) fail_parse()
      for (emit_index = 1; emit_index <= key_count; emit_index += 1) {
        if (result_leaf_file[emit_index] == "") fail_parse()
        print keybox_index "\t" declared_keyboxes "\t" emit_index "\t" key_count "\t" result_chain_index[emit_index] "\t" result_leaf_file[emit_index] "\t" result_issuer_file[emit_index]
        delete result_chain_index[emit_index]
        delete result_leaf_file[emit_index]
        delete result_issuer_file[emit_index]
      }
      in_keybox = 0
    }

    function write_certificate_fragment(fragment, end_at, payload_fragment, i) {
      end_at = index(fragment, end_marker)
      if (end_at > 0) {
        payload_fragment = substr(fragment, 1, end_at - 1)
      } else {
        payload_fragment = fragment
      }

      gsub(/&#([xX]0*[dD]|13);/, "", payload_fragment)
      gsub(/&#([xX]0*[aA]|10);/, "", payload_fragment)
      gsub(/\\r|\\n/, "", payload_fragment)
      gsub(/[[:space:]]/, "", payload_fragment)
      certificate_payload = certificate_payload payload_fragment

      if (end_at > 0) {
        print begin_marker > certificate_file
        for (i = 1; i <= length(certificate_payload); i += 64) {
          print substr(certificate_payload, i, 64) >> certificate_file
        }
        print end_marker >> certificate_file
        close(certificate_file)
        if (capture_position == 1) {
          leaf_file = certificate_file
        } else if (capture_position == 2) {
          issuer_file = certificate_file
        }
        capture = 0
      }
    }

    {
      line = $0
      sub(/\r$/, "", line)

      if (match(line, /<NumberOfKeyboxes>[[:space:]]*([0-9]+)[[:space:]]*<\/NumberOfKeyboxes>/, count_match)) {
        if (saw_declared_keyboxes) fail_parse()
        declared_keyboxes = count_match[1] + 0
        if (declared_keyboxes < 1) fail_parse()
        saw_declared_keyboxes = 1
      }

      if (line ~ /<Keybox([[:space:]>])/) {
        if (!saw_declared_keyboxes || in_keybox || in_key || in_chain || capture) fail_parse()
        keybox_index += 1
        if (keybox_index > declared_keyboxes) fail_parse()
        in_keybox = 1
        key_count = 0
      }

      if (line ~ /<Key([[:space:]>])/) {
        if (!in_keybox || in_key || in_chain || capture) fail_parse()
        in_key = 1
        key_count += 1
        key_index = key_count
        key_chain_count = 0
        key_chain_index = 0
        key_leaf_file = ""
        key_issuer_file = ""
      }

      if (index(line, "<CertificateChain") > 0) {
        if (!in_keybox || !in_key || in_chain || capture) fail_parse()
        in_chain = 1
        chain_index += 1
        key_chain_count += 1
        if (key_chain_count > 1) fail_parse()
        certificate_position = 0
        declared_certificates = 0
        saw_declared_certificates = 0
        leaf_file = ""
        issuer_file = ""
      }

      if (in_chain && match(line, /<NumberOfCertificates>[[:space:]]*([0-9]+)[[:space:]]*<\/NumberOfCertificates>/, certificate_count_match)) {
        if (saw_declared_certificates) fail_parse()
        declared_certificates = certificate_count_match[1] + 0
        if (declared_certificates < 1) fail_parse()
        saw_declared_certificates = 1
      }

      if (in_chain && !capture) {
        begin_at = index(line, begin_marker)
        if (begin_at > 0) {
          certificate_position += 1
          if (certificate_position <= 2) {
            capture_position = certificate_position
            certificate_file = sprintf("%s/certificate-%06d-%02d.pem", output_dir, chain_index, capture_position)
            certificate_payload = ""
            capture = 1
            write_certificate_fragment(substr(line, begin_at + length(begin_marker)))
          }
          next
        }
      }

      if (capture) {
        write_certificate_fragment(line)
        next
      }

      if (index(line, "</CertificateChain>") > 0) {
        finish_chain()
      }

      if (line ~ /<\/Key>/) {
        finish_key()
      }

      if (line ~ /<\/Keybox>/) {
        finish_keybox()
      }
    }

    END {
      if (fatal || capture || in_chain || in_key || in_keybox) exit 2
      if (!saw_declared_keyboxes || keybox_index != declared_keyboxes) exit 2
    }
  ' >"$manifest"; then
    warn "invalid Keybox structure, declared count, Key/chain layout or certificate in $keybox_source"
    ((failure_count += 1))
    continue
  fi

  file_leaf_count=0
  declared_keybox_count=0
  current_keybox_index=0
  current_key_count=0
  current_keys_seen=0
  while IFS=$'\t' read -r keybox_index keybox_count key_index key_count chain_index certificate_file issuer_file; do
    [[ -n $keybox_index && -n $keybox_count && -n $key_index && -n $key_count && -n $chain_index && -n $certificate_file ]] || continue
    if [[ ! $keybox_index =~ ^[1-9][0-9]*$ || ! $keybox_count =~ ^[1-9][0-9]*$ || ! $key_index =~ ^[1-9][0-9]*$ || ! $key_count =~ ^[1-9][0-9]*$ ]]; then
      warn "invalid Keybox/Key index metadata in $keybox_source"
      ((failure_count += 1))
      continue
    fi
    if ((declared_keybox_count == 0)); then
      declared_keybox_count=$keybox_count
    elif ((declared_keybox_count != keybox_count)); then
      warn "inconsistent declared Keybox count in $keybox_source"
      ((failure_count += 1))
      continue
    fi
    if ((keybox_index != current_keybox_index)); then
      if ((current_keybox_index > 0 && current_keys_seen != current_key_count)); then
        warn "missing Key result in Keybox $current_keybox_index of $keybox_source"
        ((failure_count += 1))
      fi
      if ((keybox_index != current_keybox_index + 1)); then
        warn "non-contiguous Keybox index in $keybox_source"
        ((failure_count += 1))
        continue
      fi
      current_keybox_index=$keybox_index
      current_key_count=$key_count
      current_keys_seen=0
    elif ((current_key_count != key_count)); then
      warn "inconsistent Key count for Keybox $keybox_index in $keybox_source"
      ((failure_count += 1))
      continue
    fi
    if ((key_index != current_keys_seen + 1 || key_index > key_count)); then
      warn "duplicate, missing or non-contiguous Key index in Keybox $keybox_index of $keybox_source"
      ((failure_count += 1))
      continue
    fi
    if ! serial_line=$(openssl x509 -in "$certificate_file" -noout -serial 2>/dev/null); then
      warn "OpenSSL could not parse the selected leaf for Keybox $keybox_index Key $key_index in $keybox_source"
      ((failure_count += 1))
      continue
    fi
    if [[ $serial_line != *=* ]]; then
      warn "OpenSSL returned an unexpected SerialNumber for Keybox $keybox_index Key $key_index in $keybox_source"
      ((failure_count += 1))
      continue
    fi

    serial=${serial_line#*=}
    serial=${serial//:/}
    serial=${serial//[[:space:]]/}
    if [[ ! $serial =~ ^[0-9A-Fa-f]{1,128}$ ]]; then
      warn "invalid SerialNumber for Keybox $keybox_index Key $key_index in $keybox_source"
      ((failure_count += 1))
      continue
    fi
    serial=${serial,,}
    while [[ ${#serial} -gt 1 && $serial == 0* ]]; do
      serial=${serial#0}
    done

    certificate_sha256=""
    issuer_spki_sha256=""
    if ((FEATURES == 1)); then
      if [[ -z $issuer_file || ! -f $issuer_file ]]; then
        warn "issuer certificate is missing for Keybox $keybox_index Key $key_index in $keybox_source"
        ((failure_count += 1))
        continue
      fi
      if ! certificate_digest_line=$(openssl x509 -in "$certificate_file" -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null); then
        warn "could not hash leaf certificate for Keybox $keybox_index Key $key_index in $keybox_source"
        ((failure_count += 1))
        continue
      fi
      certificate_sha256=${certificate_digest_line##* }
      certificate_sha256=${certificate_sha256,,}
      if [[ ! $certificate_sha256 =~ ^[0-9a-f]{64}$ ]]; then
        warn "OpenSSL returned an invalid certificate SHA-256 digest for Keybox $keybox_index Key $key_index in $keybox_source"
        ((failure_count += 1))
        continue
      fi
      if openssl verify -no_check_time -purpose any -partial_chain -trusted "$issuer_file" "$certificate_file" >/dev/null 2>&1; then
        if ! issuer_digest_line=$(openssl x509 -in "$issuer_file" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256 2>/dev/null); then
          warn "could not hash issuer SPKI for Keybox $keybox_index Key $key_index in $keybox_source"
          ((failure_count += 1))
          continue
        fi
        issuer_spki_sha256=${issuer_digest_line##* }
        issuer_spki_sha256=${issuer_spki_sha256,,}
        if [[ ! $issuer_spki_sha256 =~ ^[0-9a-f]{64}$ ]]; then
          warn "OpenSSL returned an invalid issuer SPKI SHA-256 digest for Keybox $keybox_index Key $key_index in $keybox_source"
          ((failure_count += 1))
          continue
        fi
      else
        warn "OpenSSL could not validate the next certificate as issuer for Keybox $keybox_index Key $key_index in $keybox_source; emitting exact fingerprint only"
      fi
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$serial" "$certificate_sha256" "$issuer_spki_sha256" "$keybox_index" "$keybox_count" "$key_index" "$key_count" "$chain_index" "$keybox_source" >>"$RESULTS_FILE"
    ((current_keys_seen += 1))
    ((file_leaf_count += 1))
    ((leaf_count += 1))
  done <"$manifest"

  if ((current_keybox_index > 0 && current_keys_seen != current_key_count)); then
    warn "missing Key result in Keybox $current_keybox_index of $keybox_source"
    ((failure_count += 1))
  fi
  if ((file_leaf_count == 0 || declared_keybox_count == 0 || current_keybox_index != declared_keybox_count)); then
    warn "expected every declared Keybox and Key to produce exactly one leaf in $keybox_source"
    ((failure_count += 1))
  fi
done

((failure_count == 0)) || die "$failure_count certificate extraction error(s); no output was written"
((leaf_count > 0)) || die "no leaf certificate SerialNumber was extracted"

FINAL_FILE="$WORK_DIR/final-output"
if ((FEATURES == 1)); then
  printf 'serial_number\tcertificate_sha256\tissuer_spki_sha256\tkeybox_index\tkeybox_count\tkey_index\tkey_count\tsource_file\n' >"$FINAL_FILE"
  LC_ALL=C sort -t $'\t' -k9,9 -k4,4n -k6,6n "$RESULTS_FILE" \
    | awk -F '\t' 'BEGIN { OFS = "\t" } { print $1, $2, $3, $4, $5, $6, $7, $9 }' >>"$FINAL_FILE"
elif ((DETAILS == 1)); then
  printf 'serial_number\tkeybox_index\tkeybox_count\tkey_index\tkey_count\tsource_file\n' >"$FINAL_FILE"
  LC_ALL=C sort -t $'\t' -k9,9 -k4,4n -k6,6n "$RESULTS_FILE" \
    | awk -F '\t' 'BEGIN { OFS = "\t" } { print $1, $4, $5, $6, $7, $9 }' >>"$FINAL_FILE"
else
  LC_ALL=C sort -t $'\t' -k9,9 -k4,4n -k6,6n "$RESULTS_FILE" \
    | awk -F '\t' '{ print $1 }' >"$FINAL_FILE"
fi

if [[ -n $OUTPUT_PATH ]]; then
  output_parent=${OUTPUT_PATH%/*}
  if [[ $output_parent != "$OUTPUT_PATH" ]]; then
    [[ -d $output_parent ]] || die "output directory does not exist: $output_parent"
  fi
  mv -- "$FINAL_FILE" "$OUTPUT_PATH"
  output_count=$(awk 'END { print NR }' "$OUTPUT_PATH")
  if ((FEATURES == 1 || DETAILS == 1)); then
    ((output_count -= 1))
  fi
  printf 'Wrote %d Key result row(s) to %s\n' "$output_count" "$OUTPUT_PATH" >&2
else
  cat "$FINAL_FILE"
fi
