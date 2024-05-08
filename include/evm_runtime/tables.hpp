#pragma once

#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>
#include <eosio/asset.hpp>
#include <eosio/singleton.hpp>
#include <eosio/binary_extension.hpp>

#include <evm_runtime/types.hpp>
#include <evm_runtime/runtime_config.hpp>
#include <eosevm/block_mapping.hpp>

#include <silkworm/core/common/base.hpp>
namespace evm_runtime {

using namespace eosio;
struct [[eosio::table]] [[eosio::contract("evm_contract")]] account {
    enum class flag : uint32_t {
        frozen = 0x1
    };

    uint64_t    id;
    bytes       eth_address;
    uint64_t    nonce;
    bytes       balance;
    std::optional<uint64_t> code_id;
    binary_extension<uint32_t> flags=0;

    void set_flag(flag f) {
        flags.value() |= static_cast<uint32_t>(f);
    }

    void clear_flag(flag f) {
        flags.value() &= ~static_cast<uint32_t>(f);
    }

    inline bool has_flag(flag f)const {
        return (flags.value() & static_cast<uint32_t>(f) != 0);
    }

    uint64_t primary_key()const { return id; }

    checksum256 by_eth_address()const { 
        return make_key(eth_address);
    }

    uint256be get_balance()const {
        uint256be res;
        std::copy(balance.begin(), balance.end(), res.bytes);
        return res;
    }

    EOSLIB_SERIALIZE(account, (id)(eth_address)(nonce)(balance)(code_id)(flags));
};

typedef multi_index< "account"_n, account,
    indexed_by<"by.address"_n, const_mem_fun<account, checksum256, &account::by_eth_address>>
> account_table;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] account_code {
    uint64_t    id;
    uint32_t    ref_count;
    bytes       code;
    bytes       code_hash;

    uint64_t primary_key()const { return id; }

    checksum256 by_code_hash()const { 
        return make_key(code_hash);
    }

    bytes32 get_code_hash()const {
        return to_bytes32(code_hash);
    }

    EOSLIB_SERIALIZE(account_code, (id)(ref_count)(code)(code_hash));
};

typedef multi_index< "accountcode"_n, account_code,
    indexed_by<"by.codehash"_n, const_mem_fun<account_code, checksum256, &account_code::by_code_hash>>
> account_code_table;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] storage {
    uint64_t id;
    bytes    key;
    bytes    value;

    uint64_t primary_key()const { return id; }

    checksum256 by_key()const { 
        return make_key(key);
    }

    EOSLIB_SERIALIZE(storage, (id)(key)(value));
};

typedef multi_index< "storage"_n, storage,
    indexed_by<"by.key"_n, const_mem_fun<storage, checksum256, &storage::by_key>> 
> storage_table;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] gcstore {
    uint64_t id;
    uint64_t storage_id;

    uint64_t primary_key()const { return id; }

    EOSLIB_SERIALIZE(gcstore, (id)(storage_id));
};

typedef multi_index< "gcstore"_n, gcstore> gc_store_table;

struct [[eosio::table("inevm")]] [[eosio::contract("evm_contract")]] balance_with_dust {
    asset balance;
    uint64_t dust = 0;

    bool is_zero() const { // not checking symbol
        return dust == 0 && balance.amount == 0;
    }
    bool operator==(const balance_with_dust& o) const {
        return balance == o.balance && dust == o.dust;
    }
    bool operator!=(const balance_with_dust& o) const {
        return !(*this == o);
    }

    balance_with_dust& operator+=(const intx::uint256& amount) {

        check(balance.symbol != eosio::symbol(), "symbol can't be empty in balance_with_dust");
        intx::uint256 minimum_natively_representable = pow10_const(evm_precision - balance.symbol.precision());
        uint64_t min_asset = minimum_natively_representable[0];

        const intx::div_result<intx::uint256> div_result = udivrem(amount, minimum_natively_representable);

        //asset::max_amount is conservative at 2^62-1, this means two max_amounts of (2^62-1)+(2^62-1) cannot
        // overflow an int64_t which can represent up to 2^63-1. In other words, asset::max_amount+asset::max_amount
        // are guaranteed greater than asset::max_amount without need to worry about int64_t overflow. Even more,
        // asset::max_amount+asset::max_amount+1 is guaranteed greater than asset::max_amount without need to worry
        // about int64_t overflow. The latter property ensures that if the existing value is max_amount and max_amount
        // is added with a dust roll over, an int64_t rollover still does not occur on the balance.
        //This means that we just need to check that whatever we're adding is no more than 2^62-1 (max_amount), and that
        // the current value is no more than 2^62-1 (max_amount), and adding them together will not overflow.
        check(div_result.quot <= asset::max_amount, "accumulation overflow");
        check(balance.amount <= asset::max_amount, "accumulation overflow");

        const int64_t base_amount = div_result.quot[0];
        balance.amount += base_amount;
        dust += div_result.rem[0];

        if(dust >= min_asset) {
            balance.amount++;
            dust -= min_asset;
        }

        check(balance.amount <= asset::max_amount, "accumulation overflow");

        return *this;
    }

    balance_with_dust& operator-=(const intx::uint256& amount) {

        check(balance.symbol != eosio::symbol(), "symbol can't be empty in balance_with_dust");
        intx::uint256 minimum_natively_representable = pow10_const(evm_precision - balance.symbol.precision());
        uint64_t min_asset = minimum_natively_representable[0];

        const intx::div_result<intx::uint256> div_result = udivrem(amount, minimum_natively_representable);

        check(div_result.quot <= balance.amount, "decrementing more than available");

        balance.amount -= div_result.quot[0];
        dust -= div_result.rem[0];

        if(dust & (UINT64_C(1) << 63)) {
            balance.amount--;
            dust += min_asset;
            check(balance.amount >= 0, "decrementing more than available");
        }

        return *this;
    }

    EOSLIB_SERIALIZE(balance_with_dust, (balance)(dust));
};

struct [[eosio::table]] [[eosio::contract("evm_contract")]] balance {
    name              owner;
    balance_with_dust balance;

    uint64_t primary_key() const { return owner.value; }

    EOSLIB_SERIALIZE(struct balance, (owner)(balance));
};

typedef eosio::multi_index<"balances"_n, balance> balances;

typedef eosio::singleton<"inevm"_n, balance_with_dust> inevm_singleton;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] nextnonce {
    name     owner;
    uint64_t next_nonce = 0;

    uint64_t primary_key() const { return owner.value; }

    EOSLIB_SERIALIZE(nextnonce, (owner)(next_nonce));
};

typedef eosio::multi_index<"nextnonces"_n, nextnonce> nextnonces;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] allowed_egress_account {
    name account;

    uint64_t primary_key() const { return account.value; }

    EOSLIB_SERIALIZE(allowed_egress_account, (account));
};

typedef eosio::multi_index<"egresslist"_n, allowed_egress_account> egresslist;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] message_receiver {

    enum flag : uint32_t {
        FORCE_ATOMIC = 0x1
    };

    name     account;
    name     handler;
    asset    min_fee;
    uint32_t flags;

    uint64_t primary_key() const { return account.value; }
    bool has_flag(flag f) const {
        return (flags & f) != 0;
    }

    EOSLIB_SERIALIZE(message_receiver, (account)(handler)(min_fee)(flags));
};

typedef eosio::multi_index<"msgreceiver"_n, message_receiver> message_receiver_table;

struct [[eosio::table]] [[eosio::contract("evm_contract")]] config2
{
    uint64_t next_account_id{0};

    EOSLIB_SERIALIZE(config2, (next_account_id));
};

struct evm_version_type {
    struct pending {
        uint64_t version;
        time_point time;

        bool is_active(time_point_sec genesis_time, time_point current_time)const {
            eosevm::block_mapping bm(genesis_time.sec_since_epoch());
            auto current_block_num = bm.timestamp_to_evm_block_num(current_time.time_since_epoch().count());
            auto pending_block_num = bm.timestamp_to_evm_block_num(time.time_since_epoch().count());
            return current_block_num > pending_block_num;
        }
    };

    uint64_t get_version(time_point_sec genesis_time, time_point current_time)const {
        uint64_t current_version = cached_version;
        if(pending_version.has_value() && pending_version->is_active(genesis_time, current_time)) {
            current_version = pending_version->version;
        }
        return current_version;
    }

    std::pair<uint64_t, bool> get_version_and_maybe_promote(time_point_sec genesis_time, time_point current_time) {
        uint64_t current_version = cached_version;
        bool promoted = false;
        if(pending_version.has_value() && pending_version->is_active(genesis_time, current_time)) {
            current_version = pending_version->version;
            promote_pending();
            promoted = true;
        }
        return std::make_pair(current_version, promoted);
    }

    void promote_pending() {
        eosio::check(pending_version.has_value(), "no pending version");
        cached_version = pending_version.value().version;
        pending_version.reset();
    }

    std::optional<pending> pending_version;
    uint64_t               cached_version=0;
};

struct pending_consensus_parameter_data_type {
    consensus_parameter_data_type  data;
    time_point                     pending_time;
};
struct consensus_parameter_type {

    consensus_parameter_data_type                          current;
    std::optional<pending_consensus_parameter_data_type>   pending;

    bool is_pending_active(time_point_sec genesis_time, time_point current_time)const {
        if (!pending.has_value()) return false;
        eosevm::block_mapping bm(genesis_time.sec_since_epoch());
        auto current_block_num = bm.timestamp_to_evm_block_num(current_time.time_since_epoch().count());
        auto pending_block_num = bm.timestamp_to_evm_block_num(pending->pending_time.time_since_epoch().count());
        return current_block_num > pending_block_num;
    }

    // Reference invalidated by get_consensus_param_and_maybe_promote and update_consensus_param.
    const consensus_parameter_data_type& get_consensus_param(
        time_point_sec genesis_time, time_point current_time) const {
        if (is_pending_active(genesis_time, current_time)) {
            return pending->data;
        }
        return current;
    }

    std::pair<const consensus_parameter_data_type &, bool> get_consensus_param_and_maybe_promote(
        time_point_sec genesis_time, time_point current_time) {
        if (is_pending_active(genesis_time, current_time)) {
            current = pending->data;
            pending.reset();
            // don't use make_pair as it create ref to temp objects
            return std::pair<const consensus_parameter_data_type &, bool>(current, true);
        }
        return std::pair<const consensus_parameter_data_type &, bool>(current, false);
    }

    template <typename Visitor>
    void update_consensus_param(Visitor visitor_fn, time_point current_time) {
        consensus_parameter_data_type new_pending = (pending.has_value() ? pending->data : current);
        std::visit(visitor_fn, new_pending);
        pending = pending_consensus_parameter_data_type{
            .data = new_pending, 
            .pending_time = current_time
        };
    }
};

struct [[eosio::table]] [[eosio::contract("evm_contract")]] config
{
    unsigned_int version; // placeholder for future variant index
    uint64_t chainid = 0;
    time_point_sec genesis_time;
    asset ingress_bridge_fee;
    uint64_t gas_price = 0;
    uint32_t miner_cut = 0;
    uint32_t status = 0; // <- bit mask values from status_flags
    binary_extension<evm_version_type> evm_version;
    binary_extension<consensus_parameter_type> consensus_parameter;

    binary_extension<eosio::name> token_contract; // <- default(unset) means eosio.token

    EOSLIB_SERIALIZE(config, (version)(chainid)(genesis_time)(ingress_bridge_fee)(gas_price)(miner_cut)(status)(evm_version)(consensus_parameter)(token_contract));
};

struct [[eosio::table]] [[eosio::contract("evm_contract")]] price_queue
{
    uint64_t block;
    uint64_t price;

    uint64_t primary_key()const { return block; }

    EOSLIB_SERIALIZE(price_queue, (block)(price));
};

typedef eosio::multi_index<"pricequeue"_n, price_queue> price_queue_table;

} //namespace evm_runtime
