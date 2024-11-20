# GitHub-Actions-Scanner
## Description
This repo contains semgrep rules to identify potential GitHub Actions expression injection vulnerabilities.
### ```detect-shell.yaml```
This file contains a rule to identify strings that could be interpolated and executed as malicious shell scripts. It assumes that the following inputs are attacker-controlled:
- github.event.issue.title
- github.event.issue.body
- github.event.pull_request.title
- github.event.pull_request.body

The triggers allowing access to these variables are:
- pull_request
- issues

An attacker could load these variables with malicious shell scripts, which could be executed via strings being interpolated as code. For example:

```
run: |
    echo "Title: ${{ github.event.pull_request.title }}"
```

This would result in the input string being interpolated as code, as it is executed through a temporary shell environment. 

This rule detects such cases where potential shell scripts could be executed. If there is a potentially vulnerable line it checks to see if the input is sanitised using sed (stream editor) by filtering all metacharacters which could be used maliciously.

It also allows inputs to be stored in environment variables as these are never expanded in a shell and are thus safer to use. However, it is important that these variables are surrounded in quotations when referenced as this ensures that they are treated as plain strings.

It also allows for Javascript actions to be used which are not vulnerable to shell injection attacks as the context values are passed to the action as an argument and not used to generate a shell script.

### ```detect-script.yaml```
This file contains a rule to identify strings that could be interpolated and executed as malicious Javascript scripts.

We have seen that using a Javascript action is a safer way of allowing context variables to be used in a workflow. However, when using actions/github-script, it allows you to execute Javascript directly in the workflow. In this way, attacker-controlled context variables can be loaded with malicious Javascript code to be executed in the workflow. For example:

```
uses: actions/github-script@v6
with:
  script: |
    console.log('Illegal: ${{ github.event.pull_request.title }}');
```

This allows the context variable to be interpolated as arbitrary Javascript code. 

This rule specifically checks for instances where any type of actions/github-script action is used. If it finds an instance where potential variable interpolation could occur, it reports it as an error.

## Usage
Install semgrep locally using:

```pip install semgrep```

To scan a file from the root directory using a rule:

```semgrep scan --no-git-ignore --config rules/<rule.yaml> path/to/target```

For example, running detect-shell.yaml on detect-shell.test.yaml:

```semgrep scan --no-git-ignore --config rules/detect-shell.yaml tests/detect-shell.test.yaml```

To run the testsuite from the root directory:

```semgrep --test --config rules/ tests/```

Each rule file has its own test file with multiple unit tests per file. Testcases are in the form of comments above the offending line indicating which rule should match the line.

## Trials and Tribulations

- I initially wanted to make a rule to check that whenever an environment variable is referenced, it is enclosed in quotations. However, matching this with semgrep requires that these variables be tracked across multiple lines, which is apparently quite difficult. I tried to use a lookahead to check if environment variable names appear later with quotes, but once again matching across multiples lines of yaml (instead of just plaintext) was not easy with semgrep.
- I also ran into the issue that metavariable-patterns in semgrep don't support the "pattern-not" specifier even though normal patterns do. This was necessary to separate the vulnerable matches from those that were sanitised as the "pattern-not" would ensure that the sanitised inputs no longer reported as a match. This was fixed by using a regex with a negative lookahead to ensure that vulnerable inputs only matched if not sanitised with sed afterwards.

## References
- https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions
- https://semgrep.dev/docs/writing-rules/overview
- https://semgrep.dev/r
- https://github.com/semgrep/semgrep-interfaces/blob/main/rule_schema_v1.yaml
