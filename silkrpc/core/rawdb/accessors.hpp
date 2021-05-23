/*
   Copyright 2020 The Silkrpc Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef SILKRPC_CORE_RAWDB_ACCESSORS_HPP_
#define SILKRPC_CORE_RAWDB_ACCESSORS_HPP_

#include <silkrpc/config.hpp>

#include <memory>
#include <optional>
#include <string>

#include <asio/awaitable.hpp>

#include <silkworm/common/util.hpp>

#include <silkrpc/common/util.hpp>

namespace silkrpc::core::rawdb {

using Walker = std::function<bool(silkworm::Bytes&, silkworm::Bytes&)>;
using ChangeSetWalker = std::function<silkworm::Bytes(uint64_t, silkworm::Bytes&)>;

class DatabaseReader {
public:
    virtual asio::awaitable<KeyValue> get(const std::string& table, const silkworm::ByteView& key) const = 0;

    virtual asio::awaitable<silkworm::Bytes> get_one(const std::string& table, const silkworm::ByteView& key) const = 0;

    virtual asio::awaitable<std::optional<silkworm::ByteView>> get_both_range(const std::string& table, const silkworm::ByteView& key, const silkworm::ByteView& subkey) const = 0;

    virtual asio::awaitable<void> walk(const std::string& table, const silkworm::ByteView& start_key, uint32_t fixed_bits, Walker w) const = 0;
};

} // namespace silkrpc::core::rawdb

#endif  // SILKRPC_CORE_RAWDB_ACCESSORS_HPP_
