#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/asset.hpp>

using namespace eosio;

CONTRACT r4ndomnumb3r : public contract
{
public:
    using contract::contract;

    TABLE account
    {
        asset balance;
        uint64_t primary_key() const { return balance.symbol.code().raw(); }
    };
    typedef multi_index<"accounts"_n, account> accounts;

    TABLE rng
    {
        checksum256 value;
    };
    using rng_t = singleton<"rng"_n, rng>;

    ACTION generate();
};
