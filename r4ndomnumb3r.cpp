#include "r4ndomnumb3r.hpp"
#include <eosio/crypto.hpp>
#include <eosio/crypto_ext.hpp>
#include <eosiolib/contracts/eosio/transaction.hpp>
#include <cstring>

void r4ndomnumb3r::generate(const uint64_t& salt)
{
    size_t tx_size = transaction_size();
    std::vector<char> data(
        tx_size +           // size of currently executing, serialized transaction
        sizeof(uint64_t) +  // eosio.rex token balance
        sizeof(uint64_t) +  // eosio.ram token balance
        sizeof(uint32_t) +  // current block number
        32 +                // previous value
        sizeof(uint64_t)    // salt
    );

    // 1) Transaction
    // The first part of our entropy mix is the currently executing, serialized transaction of a particular user/account.
    read_transaction(data.data(), tx_size);

    // 2) A second source of entropy are the EOS token balances of REX and RAM system contracts.
    accounts accs("eosio.token"_n, "eosio.rex"_n.value);
    account rex = accs.get(5459781);    // 5459781 == raw "EOS" symbol code
    std::memcpy(data.data() + tx_size, &rex.balance.amount, sizeof(uint64_t));
    accs = accounts("eosio.token"_n, "eosio.ram"_n.value);
    account ram = accs.get(5459781);    // 5459781 == raw "EOS" symbol code
    std::memcpy(data.data() + tx_size + sizeof(uint64_t), &ram.balance.amount, sizeof(uint64_t));

    // 3) Current Block Number
    // To ensure unique random numbers for each block, the current block number is added as pseudo-randomness
    uint32_t bn = current_block_number();
    std::memcpy(data.data() + tx_size + sizeof(uint64_t) + sizeof(uint64_t), &bn, sizeof(uint32_t));

    // 4) Previous Value
    // Finally, the previously calculated random value is added to ensure unique random values for each call
    rng_t x(_self, _self.value);
    checksum256 prev_value = x.get_or_default({checksum256()}).value;
    std::memcpy(data.data() + tx_size + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t), prev_value.data(), 32);

    // 5) Salt
    std::memcpy(data.data() + tx_size + sizeof(uint64_t) + sizeof(uint64_t) + sizeof(uint32_t) + 32, &salt, sizeof(uint64_t));

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

void r4ndomnumb3r::generate2(const uint64_t& salt)
{
    uint8_t msg[BLAKE2B_BLOCKBYTES];

    //size_t tx_size = transaction_size();
    //uint64_t num_blocks = tx_size / BLAKE2B_BLOCKBYTES;
    //uint64_t num_pad_bytes = BLAKE2B_BLOCKBYTES - tx_size % BLAKE2B_BLOCKBYTES;

    //size_t tx_size = transaction_size();
    //std::vector<char> data(
    //    tx_size +           // size of currently executing, serialized transaction
    //    sizeof(uint64_t) +  // eosio.rex token balance
    //    sizeof(uint64_t) +  // eosio.ram token balance
    //    sizeof(uint32_t) +  // current block number
    //    sizeof(uint64_t)    // salt
    //);

    // 1) Transaction
    // The first part of our entropy mix is the currently executing, serialized transaction of a particular user/account.
    //read_transaction(data.data(), tx_size);
    // 2) A second source of entropy are the EOS token balances of REX and RAM system contracts.
    accounts accs("eosio.token"_n, "eosio.rex"_n.value);
    account rex = accs.get(5459781);    // 5459781 == raw "EOS" symbol code
    std::memcpy(&msg[0], &rex.balance.amount, sizeof(uint64_t));
    accs = accounts("eosio.token"_n, "eosio.ram"_n.value);
    account ram = accs.get(5459781);    // 5459781 == raw "EOS" symbol code
    std::memcpy(&msg[8], &ram.balance.amount, sizeof(uint64_t));
    // 3) Current Block Number
    // To ensure unique random numbers for each block, the current block number is added as pseudo-randomness
    uint32_t bn = current_block_number();
    std::memcpy(&msg[16], &bn, sizeof(uint32_t));
    // 4) Salt
    std::memcpy(&msg[20], &salt, sizeof(uint64_t));
    // 5) Transaction
    std::memset(&msg[28], 0, 100);

    // get current state
    rng2_t x(_self, _self.value);
    rng2 state = x.get_or_default({
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    });

    rng2 state_new;
    uint64_t t0_os = "r4ndomnumb3r"_n.value;
    uint64_t t1_os = "r4ndomnumb3r"_n.value;

    blake2_f(
        1,
        reinterpret_cast<const char*>(&state),
        sizeof(state),
        reinterpret_cast<const char*>(msg),
        sizeof(msg),
        reinterpret_cast<const char*>(&t0_os),
        8,
        reinterpret_cast<const char*>(&t1_os),
        8,
        0,
        reinterpret_cast<char*>(&state_new),
        sizeof(state_new)
    );

    x.set(state_new, _self);
}