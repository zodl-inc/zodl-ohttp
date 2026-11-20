// Copyright © 2026 Znewco, Inc. (d/b/a Zcash Open Development Lab)
// SPDX-License-Identifier: AGPL-3.0-only
//
// This file is part of ZODL OHTTP.
//
// ZODL OHTTP is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License,
// version 3 only, as published by the Free Software Foundation.
//
// ZODL OHTTP is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Affero General Public License for more details.
//
// Commercial licensing: see COMMERCIAL-LICENSE.md.

//! `CONFIG_SOURCE=file`: the file's deny list is the one in force.

use std::net::IpAddr;

use zodl_ohttp_gateway::config::Config;
use zodl_ohttp_gateway::config_source::{self, Cli};
use zodl_ohttp_gateway::dynamic_hosts::is_connectable;

fn cli() -> Cli {
    Cli::parse([std::ffi::OsString::from("gateway")]).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// A configuration file whose deny list differs from the environment's.
fn file() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("deny-cidrs-{}.toml", std::process::id()));
    std::fs::write(
        &path,
        "schema = 1\ngateway_hosts = [\"gw.example\"]\n[dynamic_hosts]\ndeny_cidrs = [\"9.9.9.0/24\"]\n",
    )
    .unwrap();
    path
}

#[test]
fn file_mode_puts_the_files_deny_list_in_force() {
    let path = file();
    std::env::set_var("CONFIG_SOURCE", "file");
    std::env::set_var("GATEWAY_CONFIG_FILE", &path);
    std::env::set_var("DYNAMIC_HOSTS_DENY_CIDRS", "1.0.0.0/24");
    let installed = config_source::install(&cli()).unwrap();
    assert!(installed.file.is_some());
    assert!(is_connectable(ip("9.9.9.9")));
    Config::from_env().unwrap();
    assert!(!is_connectable(ip("9.9.9.9")));
    assert!(is_connectable(ip("1.0.0.1")));
    let _ = std::fs::remove_file(path);
}
