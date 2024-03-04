#!/usr/bin/env bash

# catch from https://stackoverflow.com/a/59592881
catch() {
    # catch STDOUT_VARIABLE STDERR_VARIABLE COMMAND [ARG1[ ARG2[ ...[ ARGN]]]]
    {
        IFS=$'\n' read -r -d '' "${1}";
        IFS=$'\n' read -r -d '' "${2}";
        (IFS=$'\n' read -r -d '' _ERRNO_; return "${_ERRNO_}");
    } < <((printf '\0%s\0%d\0' "$( ( ( ({ shift 2; "${@}"; echo "${?}" 1>&3-; } | tr -d '\0' 1>&4-) 4>&2- 2>&1- | tr -d '\0' 1>&4-) 3>&1- | exit "$(cat)") 4>&1-)" "${?}" 1>&2) 2>&1)
}

check() {
    local check_name=${1}; shift
    local check_type=${1}; shift

    if [[ ${check_type} == 'stderr_contains_line' ]]; then
        local check_pattern=${1}; shift
    fi

    shift

    # run the command
    local stdout
    local stderr
    catch stdout stderr "${@}"
    local retcode=$?

    case ${check_type} in
        'stderr_contains_line')
            if grep -q -e "${check_pattern}" <<<"${stderr}" &>/dev/null; then
                printf 'OK %s\n' "${check_name}"
            else
                printf 'KO %s\n' "${check_name}"
            fi
        ;;
        'stdout_contains_line')
            if grep -q -e "${check_pattern}" <<<"${stdout}" &>/dev/null; then
                printf 'OK %s\n' "${check_name}"
            else
                printf 'KO %s\n' "${check_name}"
            fi
        ;;
        'success')
            if (( "${retcode}" == 0 )); then
                printf 'OK %s\n' "${check_name}"
            else
                printf 'KO %s\n' "${check_name}"
            fi
            ;;
    esac
}

check_cli() {
    # WARN: CLI tests are very fagile!!!

    # missing configuration file
    check common_01 stderr_contains_line 'file not found' -- ./tools/mk_vendor make unknownfile --dry-run

    # unknown preset
    check preset_04 stderr_contains_line '[^.]unknownvalue[^.].*is not in configuration file' -- ./tools/mk_vendor make openssl:unknownvalue --dry-run

    # fetch
    check fetch_01 stderr_contains_line '--fetch.*cannot be empty' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --fetch=
    check fetch_02 stderr_contains_line '--fetch.*cannot be empty' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --fetch=''
    check fetch_03 stderr_contains_line '--fetch.*cannot be empty' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --fetch ''
    check fetch_04 stderr_contains_line '[^.]unknownvalue[^.].*is not in configuration file' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --fetch=unknownvalue

    # patch
    check patch_01 stderr_contains_line '[^.]unknownvalue[^.].*is not in configuration file' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --patch=unknownvalue
    check patch_02 success -- ./tools/mk_vendor make openssl:openssl111k --dry-run --patch=

    # build
    check build_01 stderr_contains_line '[^.]vendor.build[^.].*empty.*' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --build=
    check build_02 stderr_contains_line '[^.]unknownvalue[^.].*is not in configuration file.*' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --build=unknownvalue

    # options
    check options_01 success -- ./tools/mk_vendor make openssl:openssl111k --dry-run --options=

    # name
    check name_01 success -- ./tools/mk_vendor make openssl:openssl111k --dry-run --name=anewname
    check name_02 success -- ./tools/mk_vendor make openssl:openssl111k --dry-run --name anewname
    check name_03 success -- ./tools/mk_vendor make openssl:openssl111k --dry-run -n anewname
    check name_04 stderr_contains_line '--name.*cannot be empty' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --name=
    check name_05 stderr_contains_line '--name.*cannot be empty' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --name ''
    check name_06 stderr_contains_line '-n.*cannot be empty' -- ./tools/mk_vendor make openssl:openssl111k --dry-run -n ''
    check name_07 stderr_contains_line 'missing mandatory value.*--name' -- ./tools/mk_vendor make openssl:openssl111k --dry-run --name
    check name_08 stderr_contains_line 'missing mandatory value.*-n' -- ./tools/mk_vendor make openssl:openssl111k --dry-run -n
}

NB_OK=0
NB_KO=0
FAILURE=()

while IFS=$'\n' read -r result
do
    printf '%s\n' "${result}"

    read -r status name <<<"${result}"
    if [[ ${status} = OK ]]; then
        (( NB_OK=NB_OK+1 ))
    elif [[ ${status} = KO ]]; then
        (( NB_KO=NB_KO+1 ))
        FAILURE+=( "${name}" )
    fi
done < <(check_cli)

printf '\nsuccess: %d, failure: %s, total: %d\n' "${NB_OK}" "${NB_KO}" "$(( NB_OK + NB_KO ))"
exit $(( NB_KO != 0 ))