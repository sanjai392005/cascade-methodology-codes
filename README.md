# A Controlled Experimental Methodology for Evaluating LLM-Based Vulnerability Repair Using Cascaded Program Analysis Context

Code, data and archived outputs for manuscript jcp-4438912 by Rohini Murugesan, Sanjai K C K, Ashwin Kathirvel, Rishab Nair, Anand R Nair, Sumit Kumar Gautam, Vibhanshu Dhote and M Sethumadhavan (TIFAC-CORE in Cyber Security, Amrita Vishwa Vidyapeetham; LG Soft India).

Everything below is taken from the files in this repository and from the manuscript. Where the two differ, or where a step is not automated, the [Reproduction notes](#10-reproduction-notes) say so.

## Contents

1. [Overview](#1-overview)
2. [Methodology](#2-methodology)
3. [Repository structure](#3-repository-structure)
4. [What each folder contains](#4-what-each-folder-contains)
5. [Prerequisites and dependencies](#5-prerequisites-and-dependencies)
6. [Installation and setup](#6-installation-and-setup)
7. [Running the experiments](#7-running-the-experiments)
8. [How classifications are generated](#8-how-classifications-are-generated)
9. [How calculations and results are generated](#9-how-calculations-and-results-are-generated)
10. [Reproduction notes](#10-reproduction-notes)
11. [Citation and license](#11-citation-and-license)
12. [Releases](#12-releases)

## 1. Overview

The study asks one question (RQ1 in the manuscript): within a defined experimental setting, how do the repair outcomes of a fixed LLM vary across different program-analysis context configurations?

To answer it, the same model, `Qwen/Qwen2.5-14B-Instruct`, is asked to repair the same vulnerable files while the context in the prompt is made progressively richer. Cases the model fails to fix at one level are escalated to the next (a cascade). The repository holds two evaluation arms:

| Arm | Corpus | Context levels | Where |
|---|---|---|---|
| Juliet | 100 vulnerable C/C++ programs from Juliet Test Suite 1.3, nine CWE classes | L0, L1, L2, L3 | `L0/`, `L1/`, `L2/`, `L3/`, `Juliet C C++ 100 Selected Cases/` |
| DVWA | 53 PHP files from 18 modules of the Damn Vulnerable Web Application | L0, L1, L2 | `DVWA/` |

Each generated patch is classified into one of three mutually exclusive outcomes: **CFR** (correct fix), **PIR** (plausible but incorrect) or **IFR** (invalid fix).

Results reported in the manuscript:

| Arm | Result |
|---|---|
| Juliet cascade | L0 fixes 54 of 100. Cumulative Fix Rate is 90% after L1, 93% after L2 and 93% after L3. |
| Juliet common pool (the 46 cases L0 failed) | L1 fixes 36 (78.3%), L2 fixes 29 (63.0%), L3 fixes 32 (69.6%). |
| DVWA | 39 of 53 files (73.6%) are repaired under independent validation. The automated classification that drove the cascade recorded 52 of 53 (98.1%). |

The manuscript presents these as observations for one model, one bounded sample and one validation procedure. They are not claimed to generalise to other LLMs, datasets or production software.

## 2. Methodology

### 2.1 Cascade design

All cases start at L0. A case classified CFR is marked resolved; every other case (PIR or IFR) forms the failure pool passed to the next level. The model, the decoding settings and the evaluation harness stay fixed; only the context in the prompt changes.

Because each cascade level sees a smaller and harder pool than the one before, the manuscript also runs a **common-pool comparison**: L1, L2 and L3 are each evaluated independently on the same 46 cases that L0 failed, so the three configurations share one denominator.

### 2.2 Repair model and inference settings

These are the same in every repair notebook, in both arms:

- Model: `Qwen/Qwen2.5-14B-Instruct`, loaded through Hugging Face Transformers with `device_map="auto"`.
- Quantization: 4-bit NF4, double quantization, `float16` compute (`BitsAndBytesConfig`).
- Prompt format: the model's chat template with one system message and one user message.
- Decoding: greedy (`do_sample=False`, `temperature=None`, `top_p=None`), `max_new_tokens=4096`.
- One generation per case, with no iterative refinement.
- Markdown code fences around the output are stripped before the patch is saved.

### 2.3 Juliet arm: context levels

| Level | Context in the prompt | How the context is produced | Notebook |
|---|---|---|---|
| L0 | Raw source code only | None | `L0/L0.ipynb` |
| L1 | Source code and normalized SAST findings | Enry detects the language and routes the file to a scanner; findings are reduced to CWE, severity, line and description | `L1/sast.ipynb` |
| L2 | Source code and a CPG data-flow snippet (JSON) | LLMxCPG-Q writes CPGQL queries; Joern builds the code property graph and runs them | `L2/L2_CPG_Generation.ipynb`, `L2/joernscript.py`, `L2/L2_fix.ipynb` |
| L3 | Source code, the CPG snippet and a Flawfinder report | The L2 snippet plus Flawfinder run on the original source | `L3/L3.ipynb` |

**L0.** `build_l0_prompt()` gives the model the source file and asks it to fix the vulnerabilities, preserve functionality, change only what is necessary and return only the corrected source. No CWE, location or scanner output is supplied.

**L1.** `route_scanner()` maps the Enry language to a scanner: Bandit for Python, SpotBugs for Java, Flawfinder for C, C++ and related languages, and Semgrep otherwise. Every Juliet input is C or C++, so Flawfinder is the scanner used. Each finding is normalized to one line:

```
[CWE-ID] | Severity: <level> | Line: <number> | Description: <short message>
```

Findings are not filtered, ranked or capped. If the scanner reports nothing, the block reads `No issues detected by the selected SAST scanner.` and the case is still submitted. The routing and normalization record for each case is saved to `l1_results/sast_records/<case_id>.json`.

**L2.** Context generation has two steps.

1. *Query generation* (`L2_CPG_Generation.ipynb`). `QCRI/LLMxCPG-Q`, described in the manuscript as a fine-tuned Qwen2.5-Coder-32B-Instruct, is loaded in 8-bit with `bfloat16`. For each source file it receives an instruction to write Joern CPGQL queries whose last query uses `reachableByFlows`, and to return a JSON object with a `queries` field. The input is truncated to 2048 tokens and generation is greedy with `max_new_tokens=512`. The first brace-delimited block in the output is extracted with a regular expression. If none is found the file is marked `ERROR_NO_JSON_FOUND` and skipped.
2. *Slice extraction* (`joernscript.py`). The script runs `joern-parse` to build the CPG, normalizes the queries (drops a trailing `.l` or `.toList`, removes `.codeExact(...)` filters, rewrites dotted call names to their bare name), runs the final flow query in a generated Joern script, and parses the pretty-printed flow tables into JSON. Each flow node keeps `nodeType`, `tracked`, `line`, `method` and `file`. Adjacent and duplicate nodes are compacted and identical flows are removed. A later notebook cell deletes the `source_file` and `cpg_path` keys from each snippet.

`build_l2_prompt()` then gives the repair model the source inside `<source_code>` tags and the snippet inside `<cpg_snippet>` tags, with instructions to trace source to sink in the graph, map the path back to source lines, check for sanitization or bounds checking, and fix the code without removing Juliet preprocessor directives such as `#ifdef INCLUDEMAIN`.

The manuscript states that when LLMxCPG-Q generates no query, no slice is produced and the case is recorded as IFR while staying in the denominator.

**L3.** `build_l3_prompt()` supplies three blocks: `<source_code>`, `<cpg_snippet>` and `<static_analysis_report>`. The prompt tells the model to treat the CPG analysis as primary and the Flawfinder report as supplementary confirmation. Flawfinder is run directly on the original source at generation time and formatted as `Line <n>: [<name>]  Risk Level <level>  (<CWEs>)`.

The system message is `You are a secure code repair assistant.` in the L0 and L1 notebooks and `You are an expert SAST agent specializing in CPG analysis and secure code repair.` in the L2 and L3 notebooks.

### 2.4 DVWA arm: context levels

| Level | Context in the prompt |
|---|---|
| L0 | Raw PHP source only |
| L1 | Source, Semgrep SAST findings, and an application-context block where one is defined for the module |
| L2 | Source, SAST findings, DAST findings (OWASP ZAP alerts and ffuf endpoints), application context, and vulnerability-specific repair guidance where defined |

The notebook loads the low, medium and high variants of 18 DVWA modules (54 files). `impossible.php` is DVWA's own reference fix and is never loaded as a case. One file, `api_high`, is excluded after the run because it contains no user input and nothing to repair, leaving 53 evaluated files.

Static findings come from Semgrep with the `p/php`, `p/owasp-top-ten` and `p/javascript` rulesets. Dynamic findings come from ffuf, OWASP ZAP and Nuclei run against DVWA in Docker at security level low. CELL 5 of the notebook indexes the ZAP and ffuf entries of the DAST report by module, and these are what the L2 prompt contains. Because the index is per module, the three security-level variants of a module receive the same runtime evidence. The application-context blocks (`VULN_FRONTEND_CONTEXT`) and repair-guidance blocks (`VULN_L2_HINTS`) are defined in CELL 2 of the notebook.

After the cascade, the automated labels are checked against four independent oracles (manual review, exploit replay, a behavioural smoke test, and a target-weakness check), and a small ablation on the three Open Redirect cases separates the effect of DAST evidence from the effect of repair guidance. Full detail is in [`DVWA/README.md`](DVWA/README.md) and Section 6 of the manuscript.

## 3. Repository structure

```
cascade-methodology-codes/
├── Juliet C C++ 100 Selected Cases/     100 Juliet source files in 9 CWE folders
│   ├── CWE121_Stack_Based_Buffer_Overflow/    10 files
│   ├── CWE122_Heap_Based_Buffer_Overflow/      8 files
│   ├── CWE190_Integer_Overflow/               10 files
│   ├── CWE36_Absolute_Path_Traversal/         10 files
│   ├── CWE367_TOC_TOU/                        16 files
│   ├── CWE415_Double_Free/                    10 files
│   ├── CWE416_Use_After_Free/                 14 files
│   ├── CWE510_Trapdoor/                       10 files
│   └── CWE78_OS_Command_Injection/            12 files
├── L0/
│   └── L0.ipynb                         L0 generation and evaluation
├── L1/
│   ├── sast.ipynb                       L1 generation and evaluation
│   └── testcasesupport/                 Juliet harness support files
├── L2/
│   ├── L2_CPG_Generation.ipynb          LLMxCPG-Q query generation and Joern slicing
│   ├── joernscript.py                   Joern driver called by the notebook
│   └── L2_fix.ipynb                     L2 generation and evaluation
├── L3/
│   └── L3.ipynb                         L3 generation and evaluation
├── DVWA/
│   ├── README.md                        Detailed documentation of the DVWA arm
│   ├── dvwa_automated_pipeline.ipynb    Prompts, generation, classification, validation, export
│   ├── DVWA_arm/                        SAST and DAST scanning framework, DVWA source, validation harnesses
│   └── dasttt/                          Notebook inputs and archived outputs
├── generate_sankey.py                   Sankey diagrams of the cascade
├── VERSIONS.md                          Tool, library, dataset and runtime versions
├── LICENSE                              MIT (code)
├── LICENSE-DATA                         CC BY 4.0 (manifests and results)
└── .gitignore
```

## 4. What each folder contains

### `Juliet C C++ 100 Selected Cases/`

The 100 vulnerable source files used in the Juliet arm: 65 `.c` and 35 `.cpp`, one folder per CWE class. The folder name supplies the known CWE for each case (the loaders take the digits after `CWE`). The manuscript describes the sample as purposive rather than random, selected before any repair output was generated.

### `L0/`

`L0.ipynb` installs dependencies, loads the cases, loads the model, generates one patch per case from the L0 prompt, classifies every patch and writes the L1 failure pool.

### `L1/`

- `sast.ipynb` installs the scanners and Enry, loads the cases escalated from L0, runs language detection and SAST, builds the L1 prompt, generates and classifies patches, and writes the L2 failure pool.
- `testcasesupport/` holds the Juliet harness files that every level compiles against: `io.c`, `std_testcase.h`, `std_testcase_io.h`, `std_thread.c`, `std_thread.h`, `main.cpp`, `main_linux.cpp` and `testcases.h`. All four level notebooks need this folder.

### `L2/`

- `L2_CPG_Generation.ipynb` loads LLMxCPG-Q, installs Joern, generates CPGQL queries for each source file, calls `joernscript.py`, collects the `_snippet.json` files, strips path fields and zips the result.
- `joernscript.py` builds the CPG, runs the queries and converts Joern's flow tables to JSON.
- `L2_fix.ipynb` pairs each source file with its snippet, generates patches from the L2 prompt, classifies them and writes the L3 failure pool.

### `L3/`

`L3.ipynb` pairs each source file with its CPG snippet, runs Flawfinder on the original source, generates patches from the L3 prompt and classifies them. It is the last level, so no failure pool is written.

### `DVWA/`

- `dvwa_automated_pipeline.ipynb` is the whole DVWA experiment: SAST and DAST indexing, case loading, the `classify_dvwa()` classifier and its structural verifiers, prompt builders, the three cascade levels, post-hoc validation, ablation, Wilson intervals and oracle-provenance export.
- `DVWA_arm/` is the scanning framework that produced the SAST and DAST context.
  - `DVWA/` is the DVWA application source under analysis, with its `Dockerfile` and `compose.yml`.
  - `sast_framework/` does Enry language detection and runs Semgrep, Bandit, Flawfinder and SpotBugs; `output/` holds the raw and normalized findings; `spotbugs_home/` bundles SpotBugs 4.8.6.
  - `dast_framework/` runs ffuf, OWASP ZAP and Nuclei against the application in Docker; `output/reports/dast_report_1775648770.json` is the report used as prompt input.
  - `aggregator/` correlates SAST and DAST findings. Its output, `output/aggregated_report.json`, is not used as prompt input.
  - `tests/` holds the exploit-replay harnesses (`exploit_replay.py`, `exploit_replay_l2.py`), the behavioural smoke test (`patch_tester.py`), and their logs and results.
  - `run_scan.py`, `setup.sh`, `requirements.txt`, `dvwa_ground_truth.json` and a framework `README.md`.
- `dasttt/` is the notebook's working root.
  - `dvwa_selected_v2/`: the 18 modules with `low.php`, `medium.php`, `high.php` and the `impossible.php` reference.
  - `sast_normalized.json`, `dast_report.json`: the SAST and DAST prompt inputs.
  - `dvwa_v3_l0_outputs/` (54 patches), `dvwa_v3_l1_outputs/` (17), `dvwa_v3_l2_outputs/` (11).
  - `dvwa_v3_l2_outputs_ablate_nodast/` and `dvwa_v3_l2_outputs_ablate_nohint/`: three ablation patches each.
  - `dvwa_v3_l0_results/`, `dvwa_v3_l1_results/`, `dvwa_v3_l2_results/`: progress files, automated and validated classification records, `ablation_results.json`, `final_summary.json`, and `oracle_provenance.csv` / `.json`.

### Root files

- `generate_sankey.py` draws the cascade Sankey diagrams from CSV edge lists.
- `VERSIONS.md` records the versions used in the study and corresponds to Table A24 of the manuscript.

## 5. Prerequisites and dependencies

### Hardware and accounts

- A GPU runtime. `VERSIONS.md` records an NVIDIA A100 40 GB for the repair model and an NVIDIA H100 for LLMxCPG-Q. The manuscript notes that the fp16 model needs about 28 GB of VRAM and that 4-bit quantization was used to leave headroom for the longer L2 and L3 prompts.
- Google Colab and Google Drive. The notebooks were written for Colab: they call `google.colab.drive.mount()` and read and write under `/content/drive/MyDrive/`.
- Access to the Hugging Face Hub to download `Qwen/Qwen2.5-14B-Instruct` and `QCRI/LLMxCPG-Q`.

### Juliet arm

Each notebook installs what it needs in its first cells.

| Notebook | Python packages | System packages and tools |
|---|---|---|
| `L0/L0.ipynb` | `transformers`, `accelerate`, `bitsandbytes`, `flawfinder` | `gcc`, `g++` |
| `L1/sast.ipynb` | `transformers`, `accelerate`, `bitsandbytes`, `flawfinder`, `bandit`, `semgrep` | `gcc`, `g++`, `openjdk-17-jdk-headless`, `unzip`, `curl`, `golang-go`; SpotBugs 4.8.6 (downloaded to `/opt/spotbugs`); Enry v1.3.0 (`go install github.com/go-enry/enry@v1.3.0`) |
| `L2/L2_CPG_Generation.ipynb` | The `requirements.txt` of `https://github.com/qcri/llmxcpg`, plus `transformers` | `openjdk-11-jdk`, `wget`, `unzip`; Joern, installed with `joern-install.sh` |
| `L2/L2_fix.ipynb` | `transformers`, `accelerate`, `bitsandbytes`, `flawfinder` | `gcc`, `g++` |
| `L3/L3.ipynb` | `transformers`, `accelerate`, `bitsandbytes`, `flawfinder` | `gcc`, `g++` |

### DVWA arm

- Scanning framework (`DVWA/DVWA_arm/`): Python 3.8 or higher, Docker and Go. `requirements.txt` pins `semgrep==1.157.0`, `flawfinder==2.0.19`, `bandit==1.9.4`, `requests==2.32.5`, `zaproxy==0.6.0`, `nuclei==0.1.0` and `docker==7.2.0`. The DAST step needs a Linux Docker host (ZAP runs with host networking) and free ports 8080 and 8081.
- Notebook (`dvwa_automated_pipeline.ipynb`): `transformers`, `accelerate`, `bitsandbytes`, `semgrep`, and `php-cli` for the `php -l` syntax gate.
- Validation harnesses (`DVWA/DVWA_arm/tests/`): `requests`, Docker Compose, and DVWA reachable at `http://127.0.0.1:4280`.

### Figures

`generate_sankey.py` needs `pandas` and `plotly`. PNG export also needs `kaleido`; without it the script still writes the HTML figure.

### Versions used in the study

The notebooks install packages without pinning. The versions used are recorded in [`VERSIONS.md`](VERSIONS.md); the main ones are:

| Component | Version |
|---|---|
| Qwen2.5-14B-Instruct | revision `cf98f3b3bbb457ad9e2bb7baf9a0125b6b88caa8` |
| LLMxCPG-Q | `QCRI/LLMxCPG-Q`, revision `1f48ab60420d90277207394f1254d27d3375b07e` |
| transformers / accelerate / bitsandbytes | 5.16.1 / 1.14.0 / 0.50.2 (reconstructed on 27 May 2026, not pinned at execution time) |
| Juliet Test Suite | 1.3 |
| GCC / G++ | 11.4.0 |
| Flawfinder | 2.0.19 |
| Joern | v4.0.544 |
| Enry | v1.3.0 |
| Semgrep | 1.157.0, rulesets pulled 7 April 2026 |
| OWASP ZAP / Nuclei / ffuf | 2.17.0 / 3.7.1 / 2.1.0-dev |
| DVWA | `ghcr.io/digininja/dvwa`, digest `sha256:ed35515e9111801e6e386a6fbb11165508cc7f72e0cb8da4dbb3df70182986c6` |
| PHP / Apache / Docker | 8.5.10 / 2.4.68 / 29.5.1 |

## 6. Installation and setup

### 6.1 Get the repository

```bash
git clone https://github.com/sanjai392005/cascade-methodology-codes.git
cd cascade-methodology-codes
```

### 6.2 Juliet arm (Google Colab)

The notebooks use `REPO_ROOT = Path("/content/drive/MyDrive/")` and expect these folders on Google Drive. Either upload with these names or edit the path variables in each notebook's configuration cell.

| Notebook variable | Path expected on Drive | Source in this repository |
|---|---|---|
| `DATASET_DIR` (L0) | `MyDrive/juliet_c_cpp_selected/` | `Juliet C C++ 100 Selected Cases/` |
| `HARNESS_DIR` (all levels) | `MyDrive/testcasesupport/` | `L1/testcasesupport/` |
| `INPUT_DIR` (L1) | `MyDrive/L1_handoff/` | Created by you, see 7.1 |
| `DATASET_DIR`, `CPG_DIR` (L2) | Left empty in the committed notebook | Created by you, see 7.1 |
| `DATASET_DIR`, `CPG_DIR` (L3) | `MyDrive/L3/L3 Programs/`, `MyDrive/L3/L3 CPG/` | Created by you, see 7.1 |

Every input folder uses the same layout, one subfolder per CWE class named as in the dataset:

```
<input folder>/CWE121_Stack_Based_Buffer_Overflow/<case>.c
<CPG folder>/CWE121_Stack_Based_Buffer_Overflow/<case>_snippet.json
```

No other installation is needed: the first cells of each notebook install the Python packages, compilers and tools listed in section 5.

### 6.3 DVWA scanning framework

```bash
cd DVWA/DVWA_arm
bash setup.sh
```

`setup.sh` installs Bandit, Flawfinder and Semgrep, installs ffuf, checks for Docker, and pulls the ZAP and Nuclei images. To install only the pinned Python packages:

```bash
pip install -r requirements.txt
```

### 6.4 DVWA notebook

Upload `DVWA/dasttt/` to `MyDrive/dasttt/`, or set `REPO_ROOT` in CELL 2 to the local path of `DVWA/dasttt/`. CELL 1 installs the Python packages and `php-cli` and mounts Drive. Outside Colab, install those packages yourself and skip the Drive mount.

### 6.5 Figures

```bash
pip install pandas plotly kaleido
```

## 7. Running the experiments

### 7.1 Juliet arm

Open each notebook in Colab, select a GPU runtime, and run the cells from top to bottom. Generation cells are resumable: they record each finished case in a progress file and skip it on the next run.

**Step 1: L0**

Run `L0/L0.ipynb`. It writes, under `MyDrive/`:

- `l0_outputs/<CWE folder>/<file>`: one generated patch per case
- `l0_results/l0_progress.json`: generation log
- `l0_results/l0_results.json`: per-case classification and summary
- `l0_results/l1_failure_pool.json`: every case not classified CFR

**Step 2: L1**

Copy the original vulnerable source of every case listed in `l1_failure_pool.json` into `MyDrive/L1_handoff/<CWE folder>/`. No cell does this copy. Then run `L1/sast.ipynb`. It writes:

- `l1_outputs/<CWE folder>/<file>`
- `l1_results/l1_progress.json`
- `l1_results/sast_records/<case_id>.json`
- `l1_results/l1_results.json`
- `l1_results/l2_failure_pool.json`

**Step 3: L2 context generation**

Open `L2/L2_CPG_Generation.ipynb` and upload `L2/joernscript.py` to the Colab working directory. The path variables in the committed notebook (`DIRECTORY_PATH`, `OUTPUT_DIR`, `SOURCE_DIR`, `DEST_DIR`, `TARGET_FOLDER`) hold the placeholder `"/content."`; set them to your folders. `DIRECTORY_PATH` must be a flat folder containing the source files to slice.

The notebook then:

1. clones LLMxCPG and installs its requirements:
   ```bash
   git clone https://github.com/qcri/llmxcpg.git
   cd llmxcpg && pip install -r requirements.txt && pip install transformers
   ```
2. loads `QCRI/LLMxCPG-Q`;
3. installs Java and Joern and adds Joern to `PATH`:
   ```bash
   apt-get update -qq && apt-get install -y openjdk-11-jdk wget unzip
   wget https://github.com/joernio/joern/releases/latest/download/joern-install.sh -O joern-install.sh
   chmod +x joern-install.sh
   bash ./joern-install.sh --yes
   ```
4. generates the CPGQL queries for every file in `DIRECTORY_PATH`;
5. for each file with queries, runs:
   ```bash
   python joernscript.py <source_file> <base>_queries.json <base>_cpg.bin <base>_flows.txt <base>_snippet.json
   ```
6. copies the `_snippet.json` files to `DEST_DIR`, removes `source_file` and `cpg_path` from each, and zips the folder.

The notebook contains two versions of the query-generation cell and two of the Joern cell. The second query-generation cell, under the heading "regex updated", also rejects output that has no `queries` field. The Joern cell under "data error" rewrites `.code("*` to `.codeExact("*` before running; the one under "regular joern run" does not.

`joernscript.py` can also be run on its own. It requires `joern` and `joern-parse` on `PATH`:

```bash
python L2/joernscript.py <source_file> <queries_json> [cpg_path] [flow_txt] [snippet_json]
```

The last three arguments default to `cpg.bin`, `flows.txt` and `snippet.json`.

**Step 4: L2 repair**

Arrange the L2 inputs by CWE folder as in section 6.2, set `DATASET_DIR` and `CPG_DIR` in the configuration cell of `L2/L2_fix.ipynb`, and run it. If a source file has no matching `<case>_snippet.json`, the loader prints a warning and uses `{}` as the snippet. It writes:

- `l2_re_outputs/<CWE folder>/<file>` and `<case_id>_raw_response.txt`
- `l2_re_results/l2_progress.json`
- `l2_re_results/l2_results.json`
- `l2_re_results/l3_failure_pool.json`

**Step 5: L3**

Place the sources of the cases in `l3_failure_pool.json` in `MyDrive/L3/L3 Programs/<CWE folder>/` and their snippets in `MyDrive/L3/L3 CPG/<CWE folder>/`, then run `L3/L3.ipynb`. It writes:

- `L3_rework/L3 SAST/<CWE folder>/<case_id>_sast.json`: the Flawfinder findings used in the prompt
- `l3_fix_outputs/<CWE folder>/<file>` and `<case_id>_raw_response.txt`
- `l3_fix_results/l3_progress.json`
- `l3_fix_results/l3_results.json`

**Common-pool comparison**

There is no separate notebook for it. The pool a level is evaluated on is whatever is in that notebook's input folder, so the comparison is run by giving the L1, L2 and L3 notebooks the same 46 L0 failures instead of the cascade pool.

### 7.2 DVWA arm

**Scanning and context generation**

```bash
cd DVWA/DVWA_arm
python3 run_scan.py --all  ./DVWA    # SAST, DAST and the aggregated report
python3 run_scan.py --sast ./DVWA    # static analysis only
python3 run_scan.py --dast ./DVWA    # dynamic analysis only
```

Docker must be running. `--all` writes `sast_framework/output/normalized/normalized_results.json`, `dast_framework/output/reports/dast_report_<unix-time>.json` and `output/aggregated_report.json`. To use a new scan as prompt input, copy the normalized SAST file to `DVWA/dasttt/sast_normalized.json` and the DAST report to `DVWA/dasttt/dast_report.json`. Active scanning is non-deterministic, so a new scan will not match the archived report exactly.

**Repair, classification and validation**

Run `DVWA/dvwa_automated_pipeline.ipynb`. Cells are referred to by the `CELL n` label on their first line.

- *Path A, reproduce the reported numbers from the archived outputs* (no GPU, no model, no re-scan): CELL 1, CELL 2, CELL 7, CELL 18, CELL 19, CELL 23, CELL 24.
- *Path B, full cascade* (GPU needed at CELLS 3, 9, 12, 15 and 20): CELLS 1 to 8 for setup; 9 and 10 for L0; 11 to 13 for L1; 14 to 16 for L2; 17 for the cross-level summary; 18 and 19 for validation; 20 and 21 for the ablation; 22 for L2 attribution; 23 and 24 for export.

The archived progress files list every case, so CELLS 9, 12 and 15 skip everything unless the progress files and output folders are moved aside first. Other overwrite and ordering caveats are listed in [`DVWA/README.md`](DVWA/README.md).

**Exploit replay and smoke tests**

The scripts were run from `DVWA/DVWA_arm/` and later moved into `tests/`. To re-run them, move the script back to `DVWA/DVWA_arm/` and point its path constants (`BASELINE_DIR`, `PATCHED_DIR`, `OUTPUT_DIRS`) at the folders in `DVWA/dasttt/`.

```bash
python exploit_replay.py             # 21 L0 cases, 7 modules x 3 levels
python exploit_replay_l2.py          # 4 L2 cases
python patch_tester.py               # starts DVWA with docker compose, then runs the smoke test
python patch_tester.py --skip-docker # if DVWA is already running
```

### 7.3 Sankey diagrams

```bash
python generate_sankey.py                    # every CSV in figures/
python generate_sankey.py path/to/edges.csv  # one CSV
```

The script reads edge lists from a `figures/` folder next to it and writes `<name>_generated.html` and `<name>_generated.png` there. Each CSV has the header `Source,Dest,Value`; a row may end with a colour directive, for example:

```
Source,Dest,Value
100 Test Cases,L0,100
L0,CFR @ L0,54        --> green color
L0,Escalated to L1,46    --> red color
```

`figures/` is not in the repository. If it has no CSV, the script creates `figures/sankey_l0.csv` with exactly the content above and renders it.

## 8. How classifications are generated

### 8.1 Juliet arm

All four level notebooks use the same `classify(original, fix, filename, known_cwe)` function. `known_cwe` is the CWE number in the case's folder name. The function returns the first outcome that applies.

**Pre-checks (IFR).** The patch is IFR if it is empty, identical to the original (ignoring leading and trailing whitespace), or shorter than 30% of the original (treated as the function having been deleted). A case with no output file is also IFR.

**Stage 1: Juliet test harness.** The patch is written to a temporary folder together with a copy of every file in `testcasesupport/` and compiled with `gcc` for `.c` or `g++` for `.cpp`:

```bash
gcc -DINCLUDEMAIN -fsanitize=address,undefined -fno-sanitize-recover=all \
    -I <tmpdir> <tmpdir>/fix_<file> <tmpdir>/io.c -o <tmpdir>/fix_bin -lm -lpthread
```

`-DINCLUDEMAIN` enables the `main()` inside the Juliet file. The compile step has a 30 second timeout.

- If compilation fails, the patch is IFR. A linker error for a missing `main` is reported as the model having removed the `#ifdef INCLUDEMAIN` block.
- For CWE-121, CWE-122, CWE-190, CWE-415 and CWE-416 the binary is run three times (`NUM_HARNESS_RUNS = 3`) with `ASAN_OPTIONS=detect_leaks=0` and `UBSAN_OPTIONS=print_stacktrace=1`, each with a 10 second timeout. Three runs are used because Juliet cases branch on `rand()` and `srand(time(NULL))`. A non-zero exit or a timeout on any run makes the patch IFR.
- For CWE-367, CWE-36, CWE-78 and CWE-510 (`SAST_ONLY_CWES`) the patch must still compile, but the runtime result is not used, because AddressSanitizer and UndefinedBehaviorSanitizer do not detect these semantic weaknesses.

The original file is also compiled and run for the runtime-testable classes, and whether it crashed is stored as `baseline_crashes`. That field is recorded but does not change the label.

**Stage 2: Flawfinder rescan.** `flawfinder --csv --quiet` is run on the original and on the patch, and the set of CWE numbers reported for each is collected.

- The known CWE counts as resolved if Flawfinder reported it for the original and no longer reports it for the patch. If Flawfinder never reported it for the original, it also counts as resolved.
- New CWEs are those reported for the patch but not for the original.
- **CFR**: known CWE resolved and no new CWEs.
- **PIR**: new CWEs were introduced, or the known CWE is still flagged.

Each result stores `outcome`, `reason`, `compile_ok`, `runs_ok`, `harness_reliable`, `baseline_crashes`, `known_resolved`, `orig_cwes`, `fix_cwes` and `new_cwes`.

The manuscript reports that 52 of the 100 cases fall in the five runtime-testable classes and 48 in the four classes decided by the Flawfinder rescan alone.

### 8.2 DVWA arm

`classify_dvwa()` in CELL 7 of the notebook follows the same structure.

- **Stage 0, pre-checks (IFR):** empty output, identical to the original, or shorter than 30% of the original.
- **Stage 1, syntax (IFR):** the patch fails `php -l`. There is no execution gate in this arm.
- **Stage 2, rescan:** `semgrep --config p/php --json --quiet` is run on the original and the patch. The target CWE is judged resolved in one of three ways, and the way used is stamped into the `reason` string:
  - `[semgrep]`: Semgrep flags the target CWE in the original and not in the patch.
  - `[pattern:<module>]`: Semgrep does not flag the target in the original, so a custom structural verifier for the module is applied. Verifiers exist for `csrf`, `fi`, `xss_r`, `xss_s`, `xss_d`, `javascript`, `upload`, `weak_id`, `open_redirect`, `captcha` and `authbypass`.
  - `[semgrep_blind_unverified]`: neither applies, and the patch is recorded as resolved without a check.
- **CFR**: target resolved and no new CWE in the rescan. **PIR**: a new CWE appears or the target is not resolved.

The target CWE for a file is the CWE of its first pre-generated SAST finding if it has one, otherwise the module's entry in `VULN_CWE_MAP`.

**Post-hoc validation.** The automated labels drove the cascade but are not the reported result. CELL 18 records the verdicts of four independent checks and CELL 19 applies them:

1. Manual review of the cases that reached the unverified default.
2. Exploit replay against the running application (`tests/exploit_replay.csv`, `tests/l2_exploit_replay.json`).
3. Behavioural smoke test of every patch (`tests/results.csv`: 82 patches, of which 71 pass, 7 are broken and 4 are inconclusive).
4. Target-weakness check: whether the recorded target CWE is the weakness the module is designed to exhibit.

Thirteen CFR labels were changed to PIR, twelve at L0 and one at L2. The twelve L0 cases were reclassified after the cascade had run, so they were never escalated, and the notebook marks the validated cumulative rate as a lower bound.

## 9. How calculations and results are generated

### 9.1 Juliet arm

The evaluation cell of each notebook loops over the cases, calls `classify()` and tallies the three outcomes. The save cell then writes `l<n>_results.json`:

```json
{
  "level": "L0",
  "model": "Qwen/Qwen2.5-14B-Instruct",
  "prompt_type": "raw_code_only",
  "timestamp": "<UTC time>",
  "total_cases": 100,
  "summary": {"CFR": 0, "PIR": 0, "IFR": 0, "CFR_pct": 0.0, "PIR_pct": 0.0, "IFR_pct": 0.0},
  "cases": []
}
```

- Each percentage is `round(100 * count / total_cases, 1)`.
- `cases` holds the per-case record described in section 8.1.
- The cell prints a per-CWE breakdown (N, CFR, PIR and IFR for each CWE folder), the same columns as the per-CWE tables in the manuscript (Tables 2 to 8).
- The failure pool is every case whose outcome is not CFR. It is written as `l1_failure_pool.json`, `l2_failure_pool.json` or `l3_failure_pool.json`.
- `prompt_type` is `raw_code_only`, `raw_code_plus_normalized_sast`, `code_plus_cpg` or `code_plus_sast_plus_cpg`.

The study-level metrics are defined in Section 3.3 of the manuscript and are computed from these per-level counts:

| Metric | Definition | Example from the manuscript |
|---|---|---|
| Baseline Correct Fix Rate | CFR at L0 divided by the cases evaluated at L0 | 54 / 100 = 54.0% |
| Recovery Rate | CFR at a level divided by the failures of the previous level that entered it. This is the `CFR_pct` the notebook prints for L1 and above. | L1: 36 / 46 = 78.3% |
| Cumulative Fix Rate | All cases fixed up to a level divided by the original sample | After L1: (54 + 36) / 100 = 90.0% |

The Recovery Rate has a different denominator at every level, so the manuscript uses the common-pool comparison, not the Recovery Rate, to compare context configurations.

Two further analyses in the manuscript use the same counts. The split between runtime-verified and static-rescan-only acceptances (Table 9) corresponds to the `harness_reliable` field of the per-case record. The Wilson 95% confidence intervals for the Juliet proportions (Table 23) are reproduced by the `wilson()` function in CELL 23 of the DVWA notebook when it is given the Juliet counts, for example `wilson(54, 100)` gives [44.3, 63.4]. No cell in the Juliet notebooks computes the Cumulative Fix Rate, the evidential split or the confidence intervals.

### 9.2 DVWA arm

| Step | Cell | Output |
|---|---|---|
| Automated per-level results | CELL 10, 13, 16 | `dvwa_v3_l{0,1,2}_results/l{0,1,2}_results.json` |
| Cross-level summary of the automated run | CELL 17 | Printed only |
| Apply validation verdicts, recompute tallies and cumulative counts | CELL 19 | `l0_results_validated.json`, `l2_results_validated.json` |
| Ablation on the three Open Redirect cases | CELL 20, 21 | `dvwa_v3_l2_outputs_ablate_*/`, `ablation_results.json` |
| L2 attribution by what was in each prompt | CELL 22 | Printed only |
| Wilson 95% intervals and final summary | CELL 23 | `final_summary.json` |
| Oracle provenance of every label | CELL 24 | `oracle_provenance.csv`, `oracle_provenance.json` (81 rows) |

CELL 23 computes the Wilson score interval with `z = 1.96` for the L0 fix rate, the L1 and L2 recovery rates, and the cumulative rate after each level.

Archived values:

| | Automated (`l*_results.json`) | Validated (`final_summary.json`) |
|---|---|---|
| L0 | 37 CFR, 16 PIR, 1 IFR (N = 54) | 24 CFR, 28 PIR, 1 IFR (N = 53) |
| L1 | 6 CFR, 11 PIR (N = 17) | 6 CFR, 11 PIR (N = 17) |
| L2 | 10 CFR, 1 IFR (N = 11) | 9 CFR, 1 PIR, 1 IFR (N = 11) |
| Cumulative CFR | | 24, 30 and 39 of 53 |

In the `*_results_validated.json` files only `cases` is corrected; the `summary` block is copied unchanged from the automated file. Use `cases` or `final_summary.json` for validated counts.

CELL 24 attributes every label to the oracle that decided it. For the 39 validated correct fixes the archived `oracle_provenance.csv` gives 20 exploit replay, 1 manual review, 7 structural verifier whose property was not given to the model, and 11 structural verifier whose property was also in the prompt. The last group records conformance to a specified repair pattern, not independent evidence of repair.

A table mapping each DVWA table and figure in the manuscript to the cell or file that produces it is in [`DVWA/README.md`](DVWA/README.md).

### 9.3 Figures

The cascade Sankey diagrams are produced by `generate_sankey.py` from edge-list CSVs whose values are the per-level counts (section 7.3).

## 10. Reproduction notes

These points come from reading the committed files and affect anyone re-running the Juliet arm.

- **Paths are specific to the original Drive layout.** `REPO_ROOT` is `/content/drive/MyDrive/` in every Juliet notebook, the L2 repair notebook leaves `DATASET_DIR` and `CPG_DIR` empty, and the CPG-generation notebook uses the placeholder `"/content."`. Set them before running.
- **Hand-off between levels is manual.** Each notebook writes a failure-pool JSON, but no cell copies the failed sources into the next level's input folder or arranges the CPG snippets into CWE folders.
- **One committed file is skipped by the loaders.** Every loader drops files whose name contains `w32`, `_winsock` or `_win32`. `CWE36_Absolute_Path_Traversal__wchar_t_listen_socket_w32CreateFile_42.cpp` matches, so the loaders read 99 of the 100 committed files.
- **Saved cell outputs are not the reported runs.** The outputs stored in the Juliet notebooks come from other runs and do not match the manuscript tables: `L0.ipynb` shows 87 cases loaded after skipping 13 Windows-only variants and a 41-case failure pool; `L2_fix.ipynb` shows 7 cases; `L3.ipynb` shows 6. The manuscript reports 100 cases and a 46-case pool at L0, 10 cases at L2 and 7 at L3.
- **Juliet outputs are not in the repository.** The generated patches, result JSONs, SAST records, CPG snippets and Sankey CSVs of the Juliet arm are written to Google Drive at run time and are not committed. The DVWA arm's patches and results are committed under `DVWA/dasttt/`.
- **A case with no CPG snippet is not marked IFR by the code.** The manuscript records such cases as IFR. The L2 and L3 loaders instead substitute `{}` for a missing snippet and classify whatever patch results.
- **Tool versions are not pinned in the notebooks.** `pip install` calls carry no versions, no model revision is passed to `from_pretrained`, and Joern is installed from the latest release. `VERSIONS.md` records what was used.
- **Regenerated patches may differ.** Decoding is greedy, but the model runs in 4-bit quantization, and small numerical differences between GPUs, drivers and library versions can change a token. For the DVWA arm the archived patches are the reference artifact.

## 11. Citation and license

If you use this repository, please cite the manuscript:

> Rohini Murugesan, Sanjai K C K, Ashwin Kathirvel, Rishab Nair, Anand R Nair, Sumit Kumar Gautam, Vibhanshu Dhote and M Sethumadhavan. "A Controlled Experimental Methodology for Evaluating LLM-Based Vulnerability Repair Using Cascaded Program Analysis Context." Manuscript jcp-4438912.

The code in this repository is released under the MIT License (see [`LICENSE`](LICENSE)). The DVWA application source under `DVWA/DVWA_arm/DVWA/` carries its own licence file, `COPYING.txt`.

Manifests and experimental results authored for this project are licensed under the Creative Commons Attribution 4.0 International license (CC BY 4.0); see [`LICENSE-DATA`](LICENSE-DATA). Third-party source code, datasets and bundled dependencies retain their original licenses and notices.

## 12. Releases

### [v1.0](https://github.com/sanjai392005/cascade-methodology-codes/releases/tag/v1.0)

Initial release of the cascaded program-analysis context methodology code and archived artifacts, including:

- Juliet and DVWA experiment notebooks and supporting scripts.
- Archived DVWA results and validation outputs.
- Reproduction documentation and recorded tool versions.
- MIT licensing for project code and CC BY 4.0 licensing for project manifests and results.
