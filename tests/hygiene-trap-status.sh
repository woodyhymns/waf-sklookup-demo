#!/usr/bin/env bash
# Regression: hygiene must not turn an expected non-zero CLI into a false fail.
# Mirrors SDD-003 accept (set +e; failing upgrade; explicit $?). No BPF needed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../scripts/lib-prod-gng.sh
source "$REPO_ROOT/scripts/lib-prod-gng.sh"
export HYGIENE_DRY_RUN=1

pass_expected_fail() {
  install_hygiene_traps
  set +e
  false
  local rc=$?
  set -e
  [[ $rc -ne 0 ]]
  echo "expected-fail path reached (rc=$rc)"
  exit 0
}

pass_despite_err_reinstall() {
  # Callers such as accept-issue-34-detach-primary.sh re-trap ERR. Cleanup
  # must still not restore errexit and abort a set +e region.
  install_hygiene_traps
  trap 'hygiene_cleanup' EXIT ERR
  set +e
  false
  local rc=$?
  set -e
  [[ $rc -ne 0 ]]
  echo "ERR-reinstall expected-fail path reached (rc=$rc)"
  exit 0
}

fail_loudly() {
  install_hygiene_traps
  echo "explicit criteria fail"
  exit 1
}

run_self() {
  local self="$REPO_ROOT/tests/hygiene-trap-status.sh" rc
  set +e
  "$self" pass >/tmp/hygiene-trap-pass.out 2>&1
  rc=$?
  set -e
  [[ $rc -eq 0 ]] || {
    echo "FAIL: expected-fail path exited $rc" >&2
    cat /tmp/hygiene-trap-pass.out >&2 || true
    exit 1
  }
  set +e
  "$self" pass-err >/tmp/hygiene-trap-pass-err.out 2>&1
  rc=$?
  set -e
  [[ $rc -eq 0 ]] || {
    echo "FAIL: ERR-reinstall path exited $rc" >&2
    cat /tmp/hygiene-trap-pass-err.out >&2 || true
    exit 1
  }
  set +e
  "$self" fail >/tmp/hygiene-trap-fail.out 2>&1
  rc=$?
  set -e
  [[ $rc -eq 1 ]] || {
    echo "FAIL: explicit fail exited $rc (want 1)" >&2
    cat /tmp/hygiene-trap-fail.out >&2 || true
    exit 1
  }
  echo "hygiene trap status: PASS"
  exit 0
}

case "${1:-}" in
  pass) pass_expected_fail ;;
  pass-err) pass_despite_err_reinstall ;;
  fail) fail_loudly ;;
  ""|self) run_self ;;
  *)
    echo "usage: $0 [pass|pass-err|fail|self]" >&2
    exit 2
    ;;
esac
