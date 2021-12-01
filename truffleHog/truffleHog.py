#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

import argparse
import datetime
import hashlib
import json
import math
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid

from git import NULL_TREE
from git import Repo
from truffleHogRegexes.regexChecks import regexes


def main():
    """
    TODO: now function accept only github link. We must rewrite it to scan offline folders too
    """
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument('--json', dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--rules", dest="rules", help="Ignore default regexes and source from json file")
    parser.add_argument("--allow", dest="allow", help="Explicitly allow regexes from json list file")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth",
                        help="The max commit depth to go back when searching for secrets")
    parser.add_argument("--branch", dest="branch", help="Name of the branch to be scanned")
    parser.add_argument('-i', '--include_paths', type=argparse.FileType('r'), metavar='INCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), at least one of which must match a Git '
                             'object path in order for it to be scanned; lines starting with "#" are treated as '
                             'comments and are ignored. If empty or not provided (default), all Git object paths are '
                             'included unless otherwise excluded via the --exclude_paths option.')
    parser.add_argument('-x', '--exclude_paths', type=argparse.FileType('r'), metavar='EXCLUDE_PATHS_FILE',
                        help='File with regular expressions (one per line), none of which may match a Git object path '
                             'in order for it to be scanned; lines starting with "#" are treated as comments and are '
                             'ignored. If empty or not provided (default), no Git object paths are excluded unless '
                             'effectively excluded via the --include_paths option.')
    parser.add_argument("--repo_path", type=str, dest="repo_path",
                        help="Path to the cloned repo. If provided, git_url will not be used")
    parser.add_argument("--cleanup", dest="cleanup", action="store_true", help="Clean up all temporary result files")
    parser.add_argument('git_url', type=str, help='URL for secret searching')
    parser.set_defaults(regex=False)
    parser.set_defaults(rules={})
    parser.set_defaults(allow={})
    parser.set_defaults(max_depth=1000000)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=True)
    parser.set_defaults(branch=None)
    parser.set_defaults(repo_path=None)
    parser.set_defaults(cleanup=False)
    args = parser.parse_args()
    if args.rules:
        try:
            with open(args.rules, "r") as ruleFile:
                rules = json.loads(ruleFile.read())
                for rule in rules:
                    rules[rule] = re.compile(rules[rule])
        except (IOError, ValueError):
            raise "Error reading rules file"
        for regex in dict(regexes):
            del regexes[regex]
        for regex in rules:
            regexes[regex] = rules[regex]
    allow = {}
    if args.allow:
        try:
            with open(args.allow, "r") as allowFile:
                allow = json.loads(allowFile.read())
                for rule in allow:
                    allow[rule] = read_pattern(allow[rule])
        except (IOError, ValueError):
            raise "Error reading allow file"

    # read & compile path inclusion/exclusion patterns
    path_inclusions = []
    path_exclusions = []
    if args.include_paths:
        for pattern in {line[:-1].lstrip() for line in args.include_paths}:
            if pattern and not pattern.startswith('#'):
                path_inclusions.append(re.compile(pattern))
    if args.exclude_paths:
        for pattern in {line[:-1].lstrip() for line in args.exclude_paths}:
            if pattern and not pattern.startswith('#'):
                path_exclusions.append(re.compile(pattern))

    output = find_strings(
        args.git_url, args.since_commit, args.max_depth, args.output_json, args.do_regex, suppress_output=False,
        custom_regexes=regexes, branch=args.branch, repo_path=args.repo_path, path_inclusions=path_inclusions,
        path_exclusions=path_exclusions, allow=allow)
    if args.cleanup:
        clean_up(output)
    sys.exit(1 if output["found_issues"] else 0)


def read_pattern(r):
    return re.compile(r[6:]) if r.startswith("regex:") else re.compile(
        re.sub(r"((\\*\r)?\\*\n|(\\+r)?\\+n)+", r"( |\\t|(\\r|\\n|\\\\+[rn])[-+]?)*", re.escape(r)))


# noinspection SpellCheckingInspection
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
# noinspection SpellCheckingInspection
HEX_CHARS = "1234567890abcdefABCDEF"


def del_rw(name):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def shannon_entropy(data, iterator):
    """ Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


# noinspection SpellCheckingInspection
class ConsoleColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def clone_git_repo(git_url):
    project_path = tempfile.mkdtemp()
    Repo.clone_from(git_url, project_path)
    return project_path


def print_results(print_json, issue):
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printableDiff = issue['printDiff']
    if print_json:
        print(json.dumps(issue, sort_keys=True))
    else:
        cli_output(issue, branch_name, prev_commit, printableDiff)


def cli_output(issue, branch_name, prev_commit, printable_diff):
    print("~~~~~~~~~~~~~~~~~~~~~")
    print("{}Reason: {}{}".format(ConsoleColors.OKGREEN, issue['reason'], ConsoleColors.ENDC))
    print("{}Date: {}{}".format(ConsoleColors.OKGREEN, issue['date'], ConsoleColors.ENDC))
    print("{}Hash: {}{}".format(ConsoleColors.OKGREEN, issue['commitHash'], ConsoleColors.ENDC))
    print("{}Filepath: {}{}".format(ConsoleColors.OKGREEN, issue['path'], ConsoleColors.ENDC))
    is_v3 = sys.version_info >= (3, 0)
    print("{}Branch: {}{}".format(
        ConsoleColors.OKGREEN, branch_name if is_v3 else branch_name.encode('utf-8'), ConsoleColors.ENDC))
    print("{}Commit: {}{}".format(
        ConsoleColors.OKGREEN, prev_commit if is_v3 else prev_commit.encode('utf-8'), ConsoleColors.ENDC))
    print(printable_diff if is_v3 else printable_diff.encode('utf-8'))
    print("~~~~~~~~~~~~~~~~~~~~~")


def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob):
    stringsFound = []
    lines = printableDiff.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, ConsoleColors.WARNING + string + ConsoleColors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, ConsoleColors.WARNING + string + ConsoleColors.ENDC)
    return (
        None if not stringsFound
        else {
            'date': commit_time,
            'path': blob.b_path or blob.a_path,
            'branch': branch_name,
            'commit': prev_commit.message,
            'diff': blob.diff.decode('utf-8', errors='replace'),
            'stringsFound': stringsFound,
            'printDiff': printableDiff,
            'commitHash': prev_commit.hexsha,
            'reason': "High Entropy", })


def regex_check(printable_diff, commit_time, branch_name, prev_commit, blob, custom_regexes=None):
    custom_regexes = custom_regexes or {}
    secret_regexes = custom_regexes or regexes
    regex_matches = []
    for key in secret_regexes:
        found_strings = secret_regexes[key].findall(printable_diff)
        found_diff = None
        for found_string in found_strings:
            found_diff = printable_diff.replace(
                printable_diff, f'{ConsoleColors.WARNING}{found_string}{ConsoleColors.ENDC}')
        if found_strings:
            regex_matches.append({
                'date': commit_time, 'path': blob.b_path or blob.a_path, 'branch': branch_name,
                'commit': prev_commit.message, 'diff': blob.diff.decode('utf-8', errors='replace'),
                'stringsFound': found_strings, 'printDiff': found_diff, 'reason': key,
                'commitHash': prev_commit.hexsha})
    return regex_matches


def diff_worker(
        diff, prev_commit, branch_name, custom_regexes, do_entropy, do_regex, print_json,
        suppress_output, path_inclusions, path_exclusions, allow):
    issues = []
    for blob in diff:
        printableDiff = blob.diff.decode('utf-8', errors='replace')
        if printableDiff.startswith("Binary files") or not path_included(blob, path_inclusions, path_exclusions):
            continue
        for key in allow:
            printableDiff = allow[key].sub('', printableDiff)
        commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
        found_issues = []
        if do_entropy:
            entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob)
            if entropicDiff:
                found_issues.append(entropicDiff)
        if do_regex:
            found_issues += regex_check(printableDiff, commit_time, branch_name, prev_commit, blob, custom_regexes)
        if not suppress_output:
            for foundIssue in found_issues:
                print_results(print_json, foundIssue)
        issues += found_issues
    return issues


def handle_results(output, output_dir, found_issues):
    for foundIssue in found_issues:
        result_path = os.path.join(output_dir, str(uuid.uuid4()))
        with open(result_path, "w+") as result_file:
            result_file.write(json.dumps(foundIssue))
        output["found_issues"].append(result_path)
    return output


def path_included(blob, include_patterns=None, exclude_patterns=None):
    """Check if the diff blob object should included in analysis.

    If defined and non-empty, `include_patterns` has precedence over `exclude_patterns`, such that a blob that is not
    matched by any of the defined `include_patterns` will be excluded, even when it is not matched by any of the defined
    `exclude_patterns`. If either `include_patterns` or `exclude_patterns` are undefined or empty, they will have no
    effect, respectively. All blobs are included by this function when called with default arguments.

    :param blob: a Git diff blob object
    :param include_patterns: iterable of compiled regular expression objects; when non-empty, at least one pattern must
     match the blob object for it to be included; if empty or None, all blobs are included, unless excluded via
     `exclude_patterns`
    :param exclude_patterns: iterable of compiled regular expression objects; when non-empty, _none_ of the patterns may
     match the blob object for it to be included; if empty or None, no blobs are excluded if not otherwise
     excluded via `include_patterns`
    :return: False if the blob is _not_ matched by `include_patterns` (when provided) or if it is matched by
    `exclude_patterns` (when provided), otherwise returns True
    """
    path = blob.b_path or blob.a_path
    return not (
            include_patterns and not any(p.match(path) for p in include_patterns)
            or (exclude_patterns and any(p.match(path) for p in exclude_patterns)))


def find_strings(
        git_url, since_commit=None, max_depth=1000000, print_json=False, do_regex=False, suppress_output=True,
        custom_regexes=None, branch=None, repo_path=None, path_inclusions=None, path_exclusions=None, allow=None):
    curr_commit = None
    path_exclusions = path_exclusions or {}
    custom_regexes = custom_regexes or {}
    allow = allow or {}
    output = {"found_issues": []}
    project_path = repo_path or clone_git_repo(git_url)
    repo = Repo(project_path)
    already_searched = set()
    output_dir = tempfile.mkdtemp()

    # repo.remotes.origin.fetch(branch) if branch else repo.remotes.origin.fetch()
    for remote_branch in repo.remotes.origin.fetch(branch or None):
        since_commit_reached = False
        branch_name = remote_branch.name
        prev_commit = None
        for curr_commit in repo.iter_commits(branch_name, max_count=max_depth):
            commit_hash = curr_commit.hexsha
            if commit_hash == since_commit:
                since_commit_reached = True
                break
            # if not prev_commit, then curr_commit is the newest commit. And we have nothing to diff with.
            # But we will diff the first commit with NULL_TREE here to check the oldest code.
            # In this way, no commit will be missed.
            diff_hash = hashlib.md5((str(prev_commit) + str(curr_commit)).encode('utf-8')).digest()
            if not prev_commit or diff_hash in already_searched:
                prev_commit = curr_commit
                continue
            else:
                diff = prev_commit.diff(curr_commit, create_patch=True)
            # avoid searching the same diffs
            already_searched.add(diff_hash)
            found_issues = diff_worker(
                diff=diff, prev_commit=prev_commit, branch_name=branch_name, custom_regexes=custom_regexes,
                do_entropy=True, do_regex=do_regex, print_json=print_json, suppress_output=suppress_output,
                path_inclusions=path_inclusions, path_exclusions=path_exclusions, allow=allow)
            output = handle_results(output, output_dir, found_issues)
            prev_commit = curr_commit
        # Check if since_commit was used to check which diff should be grabbed
        if not since_commit_reached:
            diff = curr_commit.diff(NULL_TREE, create_patch=True)
        # Handle when there's no prev_commit (used since_commit on the most recent commit)
        elif prev_commit is None:
            continue
        else:
            diff = prev_commit.diff(curr_commit, create_patch=True)
        found_issues = diff_worker(
            diff, prev_commit, branch_name, custom_regexes, True, do_regex, print_json,
            suppress_output, path_inclusions, path_exclusions, allow)
        output = handle_results(output, output_dir, found_issues)
    output["project_path"] = project_path
    output["clone_uri"] = git_url
    output["issues_path"] = output_dir
    if not repo_path:
        repo.close()
        shutil.rmtree(project_path, onerror=del_rw)
    return output


def clean_up(output):
    issues_path = output.get("issues_path", None)
    if issues_path and os.path.isdir(issues_path):
        shutil.rmtree(output["issues_path"])


if __name__ == "__main__":
    main()
