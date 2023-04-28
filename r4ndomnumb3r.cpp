#include "r4ndomnumb3r.hpp"
#include <eosio/crypto.hpp>
#include <eosiolib/contracts/eosio/transaction.hpp>
#include <cstring>

void r4ndomnumb3r::generate()
{
    size_t tx_size = transaction_size();
    std::vector<char> data(
        tx_size +       // size of currently executing, serialized transaction
        8 +             // eosio.rex token balance
        8 +             // eosio.ram token balance
        4 +             // current block number
        32              // previous value
    );

    // 1) Transaction
    // The first part of our entropy mix is the currently executing, serialized transaction of a particular user/account.
    read_transaction(data.data(), tx_size);

    // 2) A second source of entropy are the EOS token balances of REX and RAM system contracts.
    accounts accs("eosio.token"_n, "eosio.rex"_n.value);
    account rex = accs.get(5459781);    // 5459781 == raw "EOS" symbol code
    std::memcpy(data.data() + tx_size, &rex.balance.amount, 8);
    accs = accounts("eosio.token"_n, "eosio.ram"_n.value);
    account ram = accs.get(5459781);    // 5459781 == raw "EOS" symbol code
    std::memcpy(data.data() + tx_size + 8, &ram.balance.amount, 8);

    // 3) Current Block Number
    // To ensure unique random numbers for each block, the current block number is added as pseudo-randomness
    uint32_t bn = current_block_number();
    std::memcpy(data.data() + tx_size + 8 + 8, &bn, 4);

    // 4) Previous Value
    // Finally, the previously calculated random value is added to ensure unique random values for each call
    rng_t x(_self, _self.value);
    checksum256 prev_value = x.get_or_default({checksum256()}).value;
    std::memcpy(data.data() + tx_size + 8 + 8 + 4, prev_value.data(), 32);

    /*
    // print digest as hex string
    uint64_t N = tx_size + 8 + 8 + 4 + 32;
    constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string s(2 + N * 2, ' ');
    s[0] = '0';
    s[1] = 'x';
    for(uint64_t i = 0; i < N; i++)
    {
        s[2 + 2*i]     = hexmap[(data[i] & 0xF0) >> 4];
        s[2 + 2*i+1]   = hexmap[ data[i] & 0x0F      ];
    }
    check(0, s);
    */

    // Calculate and set the new random value
    checksum256 value = sha256(data.data(), data.size());
    x.set({value}, _self);
}