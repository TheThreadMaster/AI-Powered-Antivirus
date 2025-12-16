# Quarantine Service Module

This directory contains all files related to file quarantine operations.

## Files

- `quarantine_manager.py` - Main quarantine script with SQLite database tracking
- `quarantine_algorithm.py` - Alternative quarantine algorithm (legacy/fallback)

## Usage

These scripts are used by the `threat_actions.py` service module, which provides programmatic access to quarantine functionality.

## Features

- SQLite database tracking
- SHA256 hash computation
- Filename obfuscation
- Permission locking
- Metadata storage
- Restore and purge capabilities

## Database

Quarantine metadata is stored in: `~/.quarantine/quarantine.db`

## Quarantine Directory

Quarantined files are stored in: `~/.quarantine/`

