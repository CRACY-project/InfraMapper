# InfraMapper

InfraMapper is a plugin-based Software Composition Analysis for analysing Infrastructure as Code (IaC).
It currently supports integration with the scansible tool for analysing Ansible playbooks, with analysis for other IaC platforms coming soon.

## Requirements
- [SBT](https://www.scala-sbt.org/) version 1.11 or higher, with Scala 3.7
- Plugin-dependent requirements, see below

## Installation
Download InfraMapper and extract it to the `plugins` folder.
[Download scansible](https://github.com/softwarelanguageslab/scansible) as a zip and extract it in the `plugins`. The `plugins` folder should hence contain a folder named `scansible` or `scansible-main`.
Follow the instructions for installing scansible in the README. Make sure to activate the `uv` virtual environment, compile the `DependencyPatternMatcher`, and run the `redis` docker as outlined.

Then, navigate back to the root folder of InfraMapper and compile it as a JAR:
```sbt assembly```

## Running
InfraMapper can be used to:
1. Extract dependencies installed via Ansible playbooks and check these dependencies for reported vulnerabilities. 
2. Scan the Ansible playbook for security weaknesses

An example Ansible playbook has already been provided in the `examples` folder.

Run `./InfraMapper --help` to get an overview on how InfraMapper can be used.

### Extracting dependencies
Run `./InfraMapper dependencies --vulnerabilities <path to project folder>` to print all dependencies
installed in the Ansible playbook, with an overview of which dependencies feature reported vulnerabilities.

When running this task for the first time, it may take up to a couple of minutes, as InfraMapper must construct a cache of reported vulnerabilities.

For example:
`./InfraMapper dependencies --vulnerabilities ./examples`

### Scanning for security weaknesses
Run `./InfraMapper weaknesses <path_to_ansible_playbook>`

For example:
`./InfraMapper weaknesses ./examples/example.yaml`