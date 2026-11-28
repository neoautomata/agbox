package complete

// BashScript returns a self-contained bash completion script for agbox.
func BashScript() string {
	return `# bash completion for agbox
# Install in ~/.local/share/bash-completion/completions/agbox
# or add 'eval "$(agbox completion bash)"' to ~/.bashrc.

_agbox_ltrim_wordbreak_completions() {
  local cur="$1"
  local prefix=""
  local cand=""
  if [[ "${cur}" == *:* && "${COMP_WORDBREAKS}" == *:* ]]; then
    cand="${cur%"${cur##*:}"}"
    if (( ${#cand} > ${#prefix} )); then
      prefix="${cand}"
    fi
  fi
  if [[ "${cur}" == *=* && "${COMP_WORDBREAKS}" == *=* ]]; then
    cand="${cur%"${cur##*=}"}"
    if (( ${#cand} > ${#prefix} )); then
      prefix="${cand}"
    fi
  fi
  if [[ -n "${prefix}" ]]; then
    local i="${#COMPREPLY[@]}"
    while (( i-- > 0 )); do
      COMPREPLY[i]="${COMPREPLY[i]#"${prefix}"}"
    done
  fi
}

_agbox_completions() {
  local cur="" prev="" words=() cword=0
  if declare -F _init_completion >/dev/null 2>&1; then
    _init_completion -n := || return 0
  else
    words=("${COMP_WORDS[@]}")
    cword="${COMP_CWORD}"
    cur="${COMP_WORDS[COMP_CWORD]:-}"
  fi
  : "${prev}"

  local cmd="${words[0]:-agbox}"
  local -a args=()
  local i=1
  while (( i <= cword )); do
    args+=("${words[i]:-}")
    (( i++ ))
  done

  local raw=""
  raw="$("${cmd}" __complete -- "${args[@]}" 2>/dev/null)" || return 0

  local -a lines=()
  local line=""
  while IFS= read -r line; do
    lines+=("${line}")
  done <<< "${raw}"

  local directive="nofiles"
  local count="${#lines[@]}"
  if (( count > 0 )) && [[ "${lines[$((count - 1))]}" == :* ]]; then
    directive="${lines[$((count - 1))]#:}"
    unset 'lines[$((count - 1))]'
  fi

  COMPREPLY=()
  for line in "${lines[@]}"; do
    [[ -n "${line}" ]] || continue
    COMPREPLY+=("${line}")
  done

  case "${directive}" in
    nospace)
      if type compopt >/dev/null 2>&1; then
        compopt -o nospace 2>/dev/null || true
      fi
      ;;
    file)
      local -a file_matches=()
      local f=""
      while IFS= read -r f; do
        [[ -n "${f}" ]] || continue
        file_matches+=("${f}")
      done < <(compgen -f -- "${cur}")
      COMPREPLY+=("${file_matches[@]}")
      if type compopt >/dev/null 2>&1; then
        compopt -o filenames 2>/dev/null || true
      fi
      ;;
    dir)
      local -a dir_matches=()
      local d=""
      while IFS= read -r d; do
        [[ -n "${d}" ]] || continue
        dir_matches+=("${d}")
      done < <(compgen -d -- "${cur}")
      COMPREPLY+=("${dir_matches[@]}")
      if type compopt >/dev/null 2>&1; then
        compopt -o filenames 2>/dev/null || true
      fi
      ;;
  esac

  _agbox_ltrim_wordbreak_completions "${cur}"
}

complete -F _agbox_completions agbox
`
}
