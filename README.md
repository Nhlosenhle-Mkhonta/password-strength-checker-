
Password Strength Checker

A simple, single‑file Python tool that evaluates password strength and provides actionable feedback. Designed for local, ethical use with no external dependencies.

Overview

Purpose
Evaluate passwords for length, character diversity, entropy, and common patterns to help users and administrators improve password hygiene.
Scope
- Runs locally using only the Python standard library.
- Suitable for demonstrations, learning, and inclusion in security awareness materials.
- Not intended to process real production credentials or transmit plaintext passwords.

Features

- Length and character class checks for lowercase, uppercase, digits, and symbols.
- Entropy estimation to approximate unpredictability.
- Pattern detection for repeated characters, sequential runs, keyboard patterns, and common substrings.
- Common password detection using a small, ethical denylist.
- Scoring and advice with clear, actionable recommendations.
- Safe output includes a short hash prefix instead of storing plaintext.

Requirements

Software
- Python 3.8 or later
No third‑party packages or shell tools are required.
