# gql-finder

> Hidden GraphQL Endpoint Discovery Tool

gql-finder is a reconnaissance utility designed to discover hidden or misconfigured GraphQL endpoints by probing common path suffixes and analyzing responses using multi-layered detection logic.

It is built for authorized security testing, CTFs, training labs, and bug bounty reconnaissance.

---

## Features

### Intelligent Baseline Learning
- Learns the **homepage response**
- Learns a **404 template response**
- Compares candidates against the closest baseline

### Multi-Signal Detection Engine

By default, gql-finder flags endpoints as **interesting** using:

- `status` — Non-404 / unexpected status codes
- `ctype` — JSON or GraphQL response content types
- `graphql` — GraphQL-specific error messages and hints
- `len` — Length delta vs closest baseline
- `similarity` — Response similarity comparison vs baseline

Users can selectively enable specific signals by using the `--filter` flag
e.g
-  only status-based findings
`python gql-finder.py https://target.com --filter status`
- only GraphQL specific error and hint responses
`python gql-finder.py https://target.com --filter graphql`
- multiple filters (comma-separated)
`python gql-finder.py https://target.com --filter status,graphql,len`
- multiple filters (repeatable)
`python gql-finder.py https://target.com --filter status --filter graphql`

### Redirect-Aware Probing

Supports browser-like redirect handling:

- POST → GET on 301 / 302 / 303 (like real browsers)
- Preserves method on 307 / 308
- Configurable redirect depth


### Probing Strategy

Each candidate suffix is tested with:

- GET request
- POST request (`application/json`)
- Fallback POST shape (if required)


##  Installation

Clone the repository:

- `git clone https://github.com/kizerh/gql-finder.git`
- cd gql-finder


### Usage

Basic scan:

`python gql-finder.py https://target.com`

Verbose mode:

`python gql-finder.py https://target.com --verbose`

Disable colored output:

`python gql-finder.py https://target.com --no-color`

Use only specific detection signals:

`python gql-finder.py https://target.com --filter status,graphql`

Follow up to 3 redirects:

`python gql-finder.py https://target.com --max-redirects 3`

Preserve POST method across redirects:

`python gql-finder.py https://target.com --redirect-mode preserve`

Use custom suffix list:

`python gql-finder.py https://target.com --suffixes custom_suffixes.json`
