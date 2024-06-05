include_guard(GLOBAL)

function(check_all_cves _target)
  check_cve("${_target}" "CVE-2015-0204")
  check_cve("${_target}" "CVE-2014-0160")
  check_cve("${_target}" "CVE-2021-3449")
endfunction()
