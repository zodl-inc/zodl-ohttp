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

//! Private parsers, exposed to the fuzz targets in `fuzz/` (feature `fuzzing` only).

/// The end of the last complete gRPC message in an upstream response body.
pub fn last_complete_grpc_message_offset(buf: &[u8]) -> usize {
    crate::proxy::last_complete_grpc_message_offset(buf)
}

/// The complete gRPC messages in `buf[..up_to]`.
pub fn count_grpc_messages(buf: &[u8], up_to: usize) -> usize {
    crate::proxy::count_grpc_messages(buf, up_to)
}
