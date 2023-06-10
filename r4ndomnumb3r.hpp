#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/asset.hpp>

using namespace eosio;

#define BLAKE2B_BLOCKBYTES 128

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

    TABLE rng2
    {
        uint64_t state_0;
        uint64_t state_1;
        uint64_t state_2;
        uint64_t state_3;
        uint64_t state_4;
        uint64_t state_5;
        uint64_t state_6;
        uint64_t state_7;
    };
    using rng2_t = singleton<"rng2"_n, rng2>;

    ACTION generate(const uint64_t& salt);

    ACTION generate2(const uint64_t& salt);
};
