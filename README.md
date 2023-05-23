# Community Black Duck GitHub Scan Action

## License & Warranty
This is a community supported [GitHub Action](https://github.com/features/actions) for launching Black Duck SCA (OSS vulnerability analysis) scans as part of a GitHub CI/CD action workflow.
It is provided under an OSS license (specified in the LICENSE file) without warranty or liability and has been developed by Synopsys field engineers as a contribution to the Synopsys user community.

Please raise issues in the repository initially, or alternatively direct questions and comments to the [Black Duck Integrations Forum](https://community.synopsys.com/s/topic/0TO34000000gGZnGAM/black-duck-integrations) in the Synopsys user community.

## Overview

The Black Duck direct scan utility supports multiple use cases:
- Run Black Duck Synopsys Detect Full (intelligent) or Rapid scans within GitHub Actions
- For `Pull Requests`, leave comments on a pull request using Rapid scan (dependencies only) to identify direct dependencies violating security policies and offer upgrade guidance including for vulnerable child dependencies (all supported package managers)
- For `Commits/Pushes`, create new fix pull requests using Rapid scan (dependencies only) to identify available upgrades for direct dependencies violating security policies including for vulnerable child dependencies (primary package managers only)
- Optionally report only newly introduced security policy violations (as compared against the last FULL **intelligent** scan)
- Optionally export Black Duck security policy violations via SARIF using Rapid scan (dependencies only); for subsequent import as code scanning alerts in GitHub (requires Advanced Security subscription in GitHub)
- Fail the check if security policies are violated

Black Duck RAPID scan policies are used to determine direct dependencies which violate security policies, allowing specific vulnerability severities and types to be covered. See the Black Duck User Guide within your server for more information on configuring security policies.

## Quick Start Guide

Follow these outline instructions to implement this utility in a GitHub repository as a GitHub Action.

1. Add GitHub repository secrets (`Settings-->Secrets-->Actions`):
   1. `BLACKDUCK_URL` with the Black Duck server URL
   2. `BLACKDUCK_API_TOKEN` with the Black Duck API token
   
2. Create at least 1 security policy for RAPID scan type in the Black Duck server:
   1. Browse to `Manage-->Policy Management`
   2. Create a new policy
   3. Ensure `Scan Mode` is set to `Rapid` (if you wish to use incremental scanning ensure both `Rapid` and `Full` scan types are specified)
   4. Add `Component Conditions` to check for vulnerabilities (for example `Highest Vulnerability Score >= 7.0`)
   
3. Create a new Action in your GitHub repository:
   1. Select `Actions` tab
   2. Select `set up a workflow yourself` if no Actions already defined, or select `New Workflow` to add a new Action
   3. Replace the `jobs:` section in the template YAML added by default with the relevant `jobs:` section for this Action - see next step
   
4. Check the package managers used in your repository:
   1. If one or more primary package managers are used (Npm, Lerna, Yarn, Pnpm, Nuget, Maven) then use either the docker container or python deployment modes (for primary package managers) - see below
   2. If one or more secondary package managers are used (including Conan, Conda, Dart, GoLang, Hex, Pypi) then use ONLY the python deployment modes (for primary and secondary package managers) - see below
   
5. OPTIONAL If you want to define specific project and version names use the action parameters `project: PROJECT` and `version: VERSION`. Note that Rapid scans do not create the Black Duck project version but can compare against previously scanned projects.

6. OPTIONAL Add the action parameter `incremental_results: true` (or add the command line option `--incremental_results true` in pythin install mode) to only report violations added since the last full run for the Black Duck project with the same name and version (requires policies configured for both `full` and `rapid` modes). The action will report all security policy violations by default. 

7. Commit the action configuration YAML file (note that the Black Duck Action should run immediately due to the commit of a new file, but there will be no security scan as no package manager file was changed)

8. OPTIONAL Manually run an intelligent (FULL) scan by selecting `Actions-->Select your new workflow-->Click on Run workflow option` within GitHub

9. Thereafter, where a package manager config file is changed within a Pull Request or Commit/push on the master/main branch, the Black Duck Action should scan for security policy violations and update comments or create Fix PRs

## Supported Technologies

The utility supports these primary package managers:
- Npm/Lerna/Pnpm/Yarn
- Maven
- NuGet

Repositories built with one or more of the primary package managers can utilise all features, run as a GitHub Action either using the pre-built container or python installation deployment modes.
Upgrade guidance will be calculated using Rapid scan (dependencies only) for all security policy violations within both direct and indirect (transitive) dependencies.
The action can create comments within Pull Requests or create fix PRs within commits/pushes to address security policy violations.

For projects built with at least one of the following secondary package managers, the action must be installed as a python/PyPi module and run directly as a command (see below).
Direct and transitive security policy violations will be reported, but upgrade guidance for all children will not be calculated, and the action will not support creating fix PRs.
- Conan
- Conda
- Dart
- GoLang
- Hex
- Pypi

The utility can support multiple package managers in a single project, although you need to ensure you choose the correct deployment mode (for primary or secondary package managers) based on the full list. For example, if you have a project using `Maven`, `npm` and `Pypi`, you will need to use the python (secondary package manager) deployment mode throughout.

The following table shows the functionality available for the supported package managers:

| Package Manager | Comment on Pull Request | Create Fix PRs for vulnerable direct dependencies | Output SARIF for code security check | Run intelligent (full) scan | Action Deployment modes  |
|-----|---|---|---|---|--------------------------|
| | Event Type: _pull_request_ | Event Type: _push_ | Event Types: _all_ | Event Types: _all_ |                          |
| | Scan Type: _rapid_ | Scan Type: _rapid_ | Scan Type: _rapid_ | Scan Type: _intelligent_ |                          |
| npm    | yes | yes | yes | yes | Docker or Python install |
| lerna  | yes | yes | yes | yes | Docker or Python install |
| yarn   | yes | yes | yes | yes | Docker or Python install |
| pnpm   | yes | yes | yes | yes | Docker or Python install |
| nuget  | yes | yes | yes | yes | Docker or Python install |
| maven  | yes | yes | yes | yes | Docker or Python install |
| conan  | yes |  | yes | yes | Python install           |
| conda  | yes |  | yes | yes | Python install           |
| dart   | yes |  | yes | yes | Python install           |
| golang | yes |  | yes | yes | Python install           |
| hex    | yes |  | yes | yes | Python install           |
| pypi   | yes |  | yes | yes | Python install           |

# Configuration

## Prerequisites

For all deployment modes, the following prerequisites are required:
- This utility requires access to a Black Duck Professional server v2021.10 or above.
- At least 1 security policy for RAPID scan must be configured (otherwise scans will show zero results as no components will violate policies).
- The following repository secrets must be configured:
  - BLACKDUCK_URL - full URL to Black Duck server (e.g. `https://server.blackduck.synopsys.com`)
  - BLACKDUCK_API_TOKEN - Black Duck API Token including scan permissions
- Ensure additional options to run successful Synopsys Detect dependency scans have been specified (either as environment variables or using the `detect_opts` parameter). For example, you may need to modify the package manager search depth, or exclude specific package managers.

For the python deployment mode (for both primary and secondary package managers):
- Only Linux runners are supported
- Ensure the required package manager(s) are installed and available on the PATH within the Action

## Modes of Operation

The action supports several activities:
- On a manual workflow (GitHub event `workflow_dispatch`), run a full (intelligent) scan
- For a Pull Request (GitHub `pull_request` event), if there are security policy violations, use Rapid scan (dependencies only) and add a comment with information on the policy violations and set the check status (all supported package managers)
- For a Commit/Push (GitHub `push` event), if there are security policy violations, use Rapid scan (dependencies only) to create fix Pull Requests to upgrade the vulnerable direct dependencies (only for the primary package managers listed above) and set the check status 
- For any activity, if there are security policy violations, use Rapid scan (dependencies only) to create a SARIF output file for import as code security issues in Github (all supported package managers)

Example complete YAML samples have been provided at the end of this document to demonstrate all modes combined.

# Deployment Modes

The action can either run as a Docker container which is downloaded dynamically (for primary package managers) or as a python package installed locally (for both primary and secondary package managers), and supports GitHub-hosted and Self-hosted Linux runners.

## Run FULL (intelligent) Scan as manual workflow - Docker deployment mode (only for Primary Package Managers)

This step will allow you to run a full scan manually.

Black Duck Full (intelligent) scans support all scan types and create a project/version in the Black Duck server.

Full scans can be used as a baseline to compare subsequent Rapid scans (use the `incremental_results` parameter within this utility to show differences since the last Full scan).

Use the YAML step below to support manual Full scans:

```yaml
      - name: Run Baseline Black Duck Scan (manual, workflow dispatch)
        if: ${{github.event_name == 'workflow_dispatch'}}
        uses: synopsys-sig-community/blackduck-direct-scan-action@v1
        with:
          bd_url: ${{ secrets.BLACKDUCK_URL }}
          bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
          mode: intelligent
        env:
          GITHUB_TOKEN: ${{ github.token }}
```

Add the following Action step configuration:

## Check Pull Request or Push - Docker Deployment Mode (only for Primary Package Managers)

The utility will support creating comments on Pull Requests or creating fix PRs to address security policy violations for all dependencies for the primary package managers. The action will also fail the code scan check.

A Black Duck Rapid scan will be run which only imports dependencies and does not create/modify a Black Duck project.

Use the following Action step configuration:

```yaml
    - name: Black Duck security scan
      uses: synopsys-sig-community/blackduck-direct-scan-action@v1
      with:
        bd_url: ${{ secrets.BLACKDUCK_URL }}
        bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
        upgrade_major: true
      env:
        GITHUB_TOKEN: ${{ github.token }}
```

You may also need to add the action parameter `bd_trustcert: true` to trust the server SSL certificate if not authenticated. See below for full descriptions of all available parameters.

## Creating SARIF for Import as GitHub Code Scanning Alerts - Docker deployment mode (for Primary Package Managers)

The utility will create a GitHub SARIF output file of security policy violations for all dependencies for the primary package managers listed above.

A Black Duck Rapid scan will be run which only imports dependencies and does not create/modify a Black Duck project.

The `sarif` parameter is used to indicate that a SARIF file should be created. Note that specifying the `sarif` parameter will stop the other operation modes (`fix_pr` or `comment_on_pr`) from running automatically. See the FAQs below for how to run the other operation modes in addition to SARIF output.

Use the YAML step below to create the SARIF file `blackduck-sarif.json`:

```yaml
    - name: Black Duck security scan SARIF
      uses: synopsys-sig-community/blackduck-direct-scan-action@v1
      with:
        bd_url: ${{ secrets.BLACKDUCK_URL }}
        bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
        upgrade_major: true
        sarif: blackduck-sarif.json  
      env:
        GITHUB_TOKEN: ${{ github.token }}
```

To import the SARIF file as code scanning alerts you would need an additional YAML step:

```yaml
    - name: "Check file existence"
      id: check_files
      uses: andstor/file-existence-action@v1
      with:
        files: "blackduck-sarif.json"
    - name: Upload SARIF file
      if: steps.check_files.outputs.files_exists == 'true'
      uses: github/codeql-action/upload-sarif@v1
      with:
        sarif_file: blackduck-sarif.json
```

## Python deployment mode (for both Primary and Secondary Package Managers)

If you are scanning a project which uses at least one secondary package manager (see list above), then you need to deploy this utility as a Python package.
The fix Pull Request operation mode is not supported for secondary package managers, and any upgrade guidance is limited to the individual package (will not include upgrading any vulnerable child dependencies).

A Black Duck Rapid scan will be run which only imports dependencies and does not create/modify a Black Duck project.

The following YAML extract will add the scan utility as a step running as a python package installed locally:

```yaml
     - name: Set up Python 3.9
       uses: actions/setup-python@v2
       with:
         python-version: 3.9
   
     - name: Install dependencies
       run: |
         python -m pip install --upgrade pip
         pip install blackduck_direct_scan_action
     - name: Run DirectGuidance Scan
       run: |
         blackduck-direct-scan-action --bd_url ${{ secrets.BLACKDUCK_URL }} --bd_token ${{ secrets.BLACKDUCK_API_TOKEN }} --upgrade_major true
       env:
          # Pass the GitHub token to the script in order to create PRs
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

You may also need to add the option `--bd_trustcert true` to the `blackduck-direct-scan-action` command to trust the server SSL certificate if not signed. See below for full descriptions of all available parameters.

## All Supported Parameters

The utility action provides a number of input parameters that can be passed using `with` or added as options to the `blackduck-direct-scan-action` command. Some input parameters have default values that should ensure default behavior if not specified.

| Property            | Default              | Description                                                                                                                                                                                                            |
|---------------------|----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| bd_url              |                  | REQUIRED The Black Duck server URL (for example `https://server.blackduck.synopsys.com`)                                                                                                                               |
| bd_token            |                 | REQUIRED The Black Duck API token (create under `User-->My Access Tokens` in the server UI)                                                                                                                            |
| bd_trustcert        | false                | Trust the certificate from the BD server (required if certificate is not fully signed)                                                                                                                                 |
| mode                | rapid                | Run either an `intelligent` scan (comprehensive, will update project version in BD server) or `rapid` scan (runs in seconds, ephemeral - use this to support the main functions of this action)                        |
| project             |                  | Black Duck project name. Not required for Rapid scans, but can be specified for BOM comparison against a previous full scan when `incremental_results` is set to true.                                                 |
| version             |                  | Black Duck version name. Not required for Rapid scans, but can be specified for BOM comparison against a previous full scan when `incremental_results` is set to true.                                                 |
| comment_on_pr       | false                | Leave a comment on the pull request with the reported issues - if specified and set to true, will override the automatic detection of the event type and stop fix PRs from being created                               |
| fix_pr              | false                | Generate a fix pull request if a vulnerable component has an available upgrade path; if specified and set to true, will override the automatic detection of the event type and stop PR comments from being created     |
| upgrade_major       | false                | Include upgrades that are beyond the current major version of the component being used - note, this can introduce a breaking change if the component's APIs are sufficiently different                                 |
| sarif               | blackduck-sarif.json | Output results in SARIF file suitable for import into GitHub as code scanning alerts                                                                                                                                   |
| incremental_results | false                | Set to `true` to filter the output to only report on newly introduced components (uses the `--detect.blackduck.rapid.compare.mode=BOM_COMPARE` option and compares configured policies against the previous full scan) |
| output_folder       | blackduck-output     | Temporary location to create output scan data (will be deleted after scan completion                                                                                                                                   |
| debug               | 0                    | Set to value `9` to see debug messages from the action                                                                                                                                                                 |
| no_files_check      | false                | Skip the validation of the changed files - by default this check will terminate the action if no package manager config files have been changed in the commit/pull request                                             |
| detect_opts         |                  | Specify Synopsys Detect scan options in a comma-delimited list without leading hyphens (e.g. `detect.detector.buildless=true,detect.maven.buildless.legacy.mode=false`)                                                | 

# Getting Support

For questions and comments, please raise issues in this repository, alternatively contact us via the [Black Duck Integrations Forum](https://community.synopsys.com/s/topic/0TO34000000gGZnGAM/black-duck-integrations).

Specify the action parameter `debug: 9` to output full logs from the action run and include logs within the issue or community post.

# Overall Example Yaml: Docker Deployment mode (for Primary Package Managers)

The following YAML file shows the configuration of the scan action for primary package managers including the ability to run a full (intelligent) scan manually:

```yaml
  name: Scan a project with Black Duck
  
  on:
    push:
      branches: [ main ]
    pull_request:
      branches: [ main ]
    workflow_dispatch:
  
  jobs:
    blackduck:
      runs-on: ubuntu-latest
      steps:
      
      - name: Checkout the code
        uses: actions/checkout@v2
        
      # Runs a Black Duck intelligent scan manually
      # This will run a "full" or "intelligent" scan, logging new components in the Black Duck Hub server
      # in order to provide real time notifications when new vulnerabilities are reported.
      - name: Run Baseline Black Duck Scan (manual, workflow dispatch)
        if: ${{github.event_name == 'workflow_dispatch'}}
        uses: synopsys-sig-community/blackduck-direct-scan-action@v1
        with:
          bd_url: ${{ secrets.BLACKDUCK_URL }}
          bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
          mode: intelligent
        env:
          GITHUB_TOKEN: ${{ github.token }}
          
      # Runs a Black Duck rapid scan for pull request/commit/push
      - name: Run Black Duck security scan on PR/commit/push
        if: ${{github.event_name != 'workflow_dispatch'}}
        uses: synopsys-sig-community/blackduck-direct-scan-action@v1
        with:
          bd_url: ${{ secrets.BLACKDUCK_URL }}
          bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
          upgrade_major: true
        env:
          # Pass the GitHub token to the script in order to create PRs
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}        
```

# Overall Example Yaml: Python Deployment Mode (for Primary and Secondary Package Managers)

The following YAML file shows the usage of the scan action for secondary package managers including the ability to run a full (intelligent) scan manually:

```yaml
  name: Scan a project with Black Duck
  
  on:
    push:
      branches: [ main ]
    pull_request:
      branches: [ main ]
    workflow_dispatch:
  
  jobs:
    blackduck:
      runs-on: ubuntu-latest
      steps:
      
      - name: Checkout the code
        uses: actions/checkout@v2
        
      # Install Python 3.9 for Black Duck Action
      - name: Set up Python 3.9
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
   
      # Install Dependencies for Black Duck Action
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install blackduck_direct_scan_action
 
      # Run manual full/intelligent scan
      - name: Run Black Duck Full Scan
        if: ${{github.event_name == 'workflow_dispatch'}}
        run: |
          blackduck-direct-scan-action --bd_url ${{ secrets.BLACKDUCK_URL }} --bd_token ${{ secrets.BLACKDUCK_API_TOKEN }} --mode intelligent
        env:
          # Pass the GitHub token to the script in order to create PRs
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}        

      # Run Black Duck rapid scan for pull request/commit/push
      - name: Run Black Duck Directguidance Scan
        if: ${{github.event_name != 'workflow_dispatch'}}
        run: |
          blackduck-direct-scan-action --bd_url ${{ secrets.BLACKDUCK_URL }} --bd_token ${{ secrets.BLACKDUCK_API_TOKEN }} --upgrade_major true
        env:
          # Pass the GitHub token to the script in order to create PRs
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}        
 ```

# FAQs

## No scan results
The utility supports Rapid (dependency) scan for checking security policy violations and either commenting on Pull Requests, creating Fix PRs on push or generating SARIF outputs.

The Black Duck Rapid dependency scan looks for supported package manager config files in the top-level folder of the repo.

Check the following potential causes:
1. The utility wil do nothing unless package manager config files (`pom.xml`, `package.json` etc.) have been modified.
2. Ensure you have created security policy violations configured for RAPID scan mode in the Black Duck server.
3. If your project only has config files in sub-folders, use the action parameter `detect_opts: detect.detector.search.depth=1`. Change the depth depending on the folder depth to traverse (for example a value of 1 would indicate depth 1 of sub-folders).
4. If using the Python deployment mode, check the required package managers are installed in the runner.
5. Examine the output and the Synopsys Detect log to see why scanning failed.
6. Add the parameter `debug: 9` (docker deployment mode) or `--debug 9` command line option (python deployment mode) and rerun

## No Black Duck project created by the scan
The utility uses Rapid (dependency) scan for checking security policy violations and either commenting on Pull Requests, creating Fix PRs on push or generating SARIF outputs.

Configure the full (intelligent) scan to create projects in Black Duck. Optionally add scan options to fail on policy violations if you wish to report issues in the pipeline in the Full scan.

## No Signature scan run
The utility uses Rapid (dependency) scan for checking security policy violations and either commenting on Pull Requests, creating Fix PRs on push or generating SARIF outputs.

Configure the full (intelligent) scan to run a Signature scan.

## Cannot connect to Black Duck server due to certificate issues
Check the `bd_url` parameter. Also try setthing the action parameter `trustcert: true` to accept the unsigned server certificate.

## How to set the BD project/version names in scans - docker mode
The project and version names are not required for Rapid scans unless you want to compare the scan against a previous Full scan.
If you want to specify project and version use the action parameters `project: MYPROJECT` and/or `version: MYVERSION` in docker deployment mode.
Alternatively add the options `--project MYPROJECT --version MYVERSION` to the `blackduck-direct-scan-action` command in python install mode. 

## How to output SARIF and Fix PR or Comment on PR operation modes together
By default the action event-type defines what operation mode will be run.
Specifying the action parameter `sarif` or command line option `--sarif` will stop the other operation modes from running.
If you wish to output SARIF in addition to comment on PR in the same step, use the following step logic:

```yaml
    - name: Black Duck Rapid security scan for Pull Request
      if: ${{github.event_name == 'pull_request'}}
      uses: synopsys-sig-community/blackduck-direct-scan-action@v1
      with:
        bd_url: ${{ secrets.BLACKDUCK_URL }}
        bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
        comment_on_pr: true
        upgrade_major: true
        sarif: blackduck-sarif.json  
      env:
        GITHUB_TOKEN: ${{ github.token }}
```

If you wish to output SARIF in addition to fix PR in the same step, use the following step logic:

```yaml
    - name: Black Duck security scan for Pull Request
      if: ${{github.event_name == 'push'}}
      uses: synopsys-sig-community/blackduck-direct-scan-action@v1
      with:
        bd_url: ${{ secrets.BLACKDUCK_URL }}
        bd_token: ${{ secrets.BLACKDUCK_API_TOKEN }}
        fix_pr: true
        upgrade_major: true
        sarif: blackduck-sarif.json  
      env:
        GITHUB_TOKEN: ${{ github.token }}
```

## Incremental scan using incremental_results option returns no results

This parameter uses the Synopsys Detect BOM_COMPARE mode to compare a Rapid scan against the results of a previous Intelligent (full) scan.

To use this mode, you need to ensure that security policies are configured for *both* Rapid and Full scan types. See the Synopsys Detect [documentation](https://sig-product-docs.synopsys.com/bundle/integrations-detect/page/introduction.html) for more details.
