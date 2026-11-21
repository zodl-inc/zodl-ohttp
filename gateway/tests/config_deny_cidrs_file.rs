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

//! The file's deny list is the one in force; the environment's is not read (a variable the
//! files set too is a warning only). One process: the list can only be set once, and the
//! refusals before it install nothing.

use std::net::IpAddr;

use zodl_ohttp_gateway::config::Config;
use zodl_ohttp_gateway::config_source::{self, Command};
use zodl_ohttp_gateway::dynamic_hosts::is_connectable;

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

/// The error of an `install_command` that must refuse.
fn refused(cmd: &Command) -> anyhow::Error {
    match config_source::install_command(cmd) {
        Ok(_) => panic!("installed"),
        Err(e) => e,
    }
}

#[test]
fn the_files_deny_list_is_in_force_and_the_environments_is_not_read() {
    let path = file();
    // Only the variables of this test.
    for name in config_source::ignored_env_variables() {
        std::env::remove_var(name);
    }
    std::env::remove_var("GATEWAY_CONFIG_FILE");
    std::env::remove_var("GATEWAY_HOST_CONFIG_FILE");
    let cmd =
        Command::parse(["gateway", "--config", path.to_str().unwrap()].map(Into::into)).unwrap();
    // CONFIG_SOURCE set to anything but `file`: refused, nothing installed.
    std::env::set_var("CONFIG_SOURCE", "compare");
    let e = format!("{:#}", refused(&cmd));
    assert!(e.contains("CONFIG_SOURCE"), "{e}");
    std::env::remove_var("CONFIG_SOURCE");
    // A setting of the environment the file leaves out: refused, by name, nothing installed.
    std::env::set_var("LWD_ADDR", "lwd.example:9067");
    let e = format!("{:#}", refused(&cmd));
    assert!(e.contains("LWD_ADDR") && !e.contains("lwd.example"), "{e}");
    std::env::remove_var("LWD_ADDR");
    // A variable the file sets too: a warning, the file's value in force.
    std::env::set_var("DYNAMIC_HOSTS_DENY_CIDRS", "1.0.0.0/24");
    let installed = config_source::install_command(&cmd).unwrap();
    assert_eq!(installed.file.path, path.to_str().unwrap());
    assert!(is_connectable(ip("9.9.9.9")));
    Config::from_env().unwrap();
    assert!(!is_connectable(ip("9.9.9.9")));
    assert!(is_connectable(ip("1.0.0.1")));
    let _ = std::fs::remove_file(path);
}
