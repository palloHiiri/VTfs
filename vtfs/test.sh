#!/usr/bin/env bash
set -euo pipefail

MNT="${1:-.}"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "OK: $*"; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

need_cmd ls
need_cmd cat
need_cmd rm
need_cmd mkdir
need_cmd rmdir
need_cmd ln
need_cmd stat
need_cmd diff
need_cmd printf

cd "$MNT" || fail "cannot cd to mountpoint: $MNT"

# Workdir to avoid clobbering user files
T="vtfs_test_$$"
mkdir "$T" || fail "cannot mkdir test dir"
cd "$T" || fail "cannot cd to test dir"

pass "entered test dir $MNT/$T"

# 0) dots
ls -la >/dev/null || fail "ls -la failed"
pass "ls -la works (includes . and ..)"

# 1) create + write + read
printf "hello world\n" > file1 || fail "write (create) failed"
out="$(cat file1)" || fail "cat failed"
[[ "$out" == "hello world" ]] || fail "unexpected content in file1: '$out'"
pass "create+write+read ok"

# 2) truncate via redirect
printf "test\n" > file1 || fail "truncate+write failed"
out="$(cat file1)" || fail "cat failed"
[[ "$out" == "test" ]] || fail "truncate content wrong: '$out'"
pass "truncate (>) ok"

# 3) unlink removes name
rm file1 || fail "rm file1 failed"
[[ ! -e file1 ]] || fail "file1 still exists after rm"
pass "unlink ok"

# 4) mkdir + rmdir empty
mkdir dir1 || fail "mkdir dir1 failed"
[[ -d dir1 ]] || fail "dir1 not a directory after mkdir"
rmdir dir1 || fail "rmdir dir1 failed"
[[ ! -e dir1 ]] || fail "dir1 still exists after rmdir"
pass "mkdir/rmdir ok"

# 5) rmdir non-empty must fail
mkdir dir2 || fail "mkdir dir2 failed"
printf "abc\n" > dir2/f || fail "create file in dir2 failed"
if rmdir dir2 2>/dev/null; then
  fail "rmdir non-empty unexpectedly succeeded"
else
  pass "rmdir non-empty correctly fails"
fi
rm dir2/f || fail "cleanup file in dir2 failed"
rmdir dir2 || fail "cleanup rmdir dir2 failed"

# 6) ASCII bytes 0..127 quick sanity (printable + few controls)
printf "A\tB\nC\rD" > ascii_test || fail "write ascii_test failed"
cat ascii_test >/dev/null || fail "read ascii_test failed"
pass "basic ASCII/control chars read/write ok"

# 7) hardlink semantics
printf "hello\n" > file1 || fail "write file1 failed"
ln file1 file3 || fail "ln file1 file3 failed"

ino1="$(stat -c '%i' file1)" || fail "stat file1 failed"
ino3="$(stat -c '%i' file3)" || fail "stat file3 failed"
[[ "$ino1" == "$ino3" ]] || fail "inode mismatch: file1=$ino1 file3=$ino3"

# data shared
printf "test\n" > file1 || fail "overwrite file1 failed"
out3="$(cat file3)" || fail "cat file3 failed"
[[ "$out3" == "test" ]] || fail "hardlink did not see updated content: '$out3'"

# remove one name, other stays readable
rm file1 || fail "rm file1 failed"
[[ ! -e file1 ]] || fail "file1 still exists after rm"
out3="$(cat file3)" || fail "cat file3 failed after rm file1"
[[ "$out3" == "test" ]] || fail "file3 content wrong after rm file1: '$out3'"

# link count should be 1 now
nlink3="$(stat -c '%h' file3)" || fail "stat nlink file3 failed"
[[ "$nlink3" == "1" ]] || fail "expected nlink=1 for file3, got $nlink3"

pass "hardlink behavior ok"

# 8) symlink creation and follow
printf "target content\n" > target_file || fail "write target_file failed"
ln -s target_file symlink_to_target || fail "ln -s target_file symlink_to_target failed"

# verify it's a symlink
[[ -L symlink_to_target ]] || fail "symlink_to_target is not a symlink"
pass "symlink creation ok"

# readlink should return target path
link_target="$(readlink symlink_to_target)" || fail "readlink failed"
[[ "$link_target" == "target_file" ]] || fail "readlink returned wrong path: '$link_target'"
pass "readlink ok"

# cat through symlink should read target content
out_via_link="$(cat symlink_to_target)" || fail "cat via symlink failed"
[[ "$out_via_link" == "target content" ]] || fail "unexpected content via symlink: '$out_via_link'"
pass "read via symlink ok"

# symlink to non-existent target should still be creatable
ln -s nonexistent_file broken_link || fail "ln -s to nonexistent failed"
[[ -L broken_link ]] || fail "broken_link is not a symlink"
pass "symlink to nonexistent ok"

# cat broken_link should fail
if cat broken_link 2>/dev/null; then
  fail "cat broken_link should have failed"
else
  pass "cat broken_link correctly fails"
fi

# rm symlink should only remove symlink, not target
rm symlink_to_target || fail "rm symlink_to_target failed"
[[ ! -e symlink_to_target ]] || fail "symlink_to_target still exists after rm"
[[ -e target_file ]] || fail "target_file was deleted (should not be)"
out_target="$(cat target_file)" || fail "cat target_file after rm symlink failed"
[[ "$out_target" == "target content" ]] || fail "target_file content changed: '$out_target'"
pass "rm symlink leaves target intact ok"

# cleanup broken link
rm broken_link || fail "rm broken_link failed"

pass "symlink behavior ok"

echo
echo "ALL TESTS PASSED in $MNT/$T"
