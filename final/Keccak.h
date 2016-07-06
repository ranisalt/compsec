#ifndef SHA3_KECCAK_H
#define SHA3_KECCAK_H

#include <stdint.h> /* size_t, uint8_t, uint64_t */
#include <array> /* std::array */
#include <sstream> /* std::stringstream */
#include <string> /* std::string */
#include <type_traits> /* std::enable_if */

namespace detail {

template<class T>
constexpr T rot_left(T i, size_t shamt)
{
    static_assert(std::is_unsigned<T>::value);
    return (i << shamt) ^ (i >> (((sizeof i) * 8u) - shamt));
}

template<size_t capacity>
class Keccak
{
    static_assert(capacity % 16 == 0, "Capacity must be 16k.");

    static constexpr auto rate = 1600u - capacity;
    static constexpr auto rateInBytes = rate / 8u;

    using lane = uint64_t; // lane = 64 bits
    using StateArray = std::array<lane, 5 * 5>; // 5 col x 5 row x 64 b

public:
    void absorb(const std::string &input)
    {
        if (phase != ABSORBING) {
            throw std::logic_error("Must not absorb after squeezing");
        }

        for (const auto &ch: input) {
            auto laneNo = npos / 8u;
            auto offset = npos % 8u;
            state[laneNo] ^= ((lane)ch % 256) << (offset * 8u);

            ++npos;
            if (npos == rateInBytes) {
                step_mappings();
                npos = 0u;
            }
        }
    }

    void pad(const std::string &suffix)
    {
        absorb(suffix);

        auto laneNo = (rateInBytes - 1) / 8u;
        auto offset = (rateInBytes - 1) % 8u;
        state[laneNo] ^= 0x80ull << (offset * 8u);

        npos = 0u;
        phase = SQUEEZING;
    }

    std::string squeeze(size_t length)
    {
        while (npos < length) {
            squeeze_more();
        }

        char ret[length];
        output.read(ret, length);
        npos -= length;
        return {ret, length};
    }

private:
    // calcula posição da lane (x, y) no state array
    static constexpr size_t lane_xy(size_t x, size_t y)
    {
        return x + 5 * y;
    }

    static StateArray theta(const StateArray &state)
    {
        /* de acordo com Keccak Reference 2.3.2 */
        std::array<lane, 5> C;
        for (auto x = 0u; x < 5u; ++x) {
            C[x] = state[lane_xy(x, 0)];
            for (auto y = 1u; y < 5u; ++y) {
                C[x] ^= state[lane_xy(x, y)];
            }
        }

        auto A = state;
        for (auto i = 0u; i < 5u; ++i) {
            // i + 4 === i - 1 (mod 5)
            auto D = C[(i + 4) % 5] xor rot_left(C[(i + 1) % 5], 1);
            for (auto j = 0u; j < 5u; ++j) {
                A[lane_xy(i, j)] ^= D;
            }
        }
        return A;
    }

    static StateArray rho(const StateArray &state)
    {
        /* de acordo com Keccak Reference 2.3.4 */
        auto A = state;
        auto x = 1u, y = 0u;
        for (auto t = 0u; t < 24; ++t) {
            auto shamt = ((t + 1) * (t + 2)) / 2;
            A[lane_xy(x, y)] = rot_left(state[lane_xy(x, y)], shamt % 64);
            auto oldX = x;
            x = y;
            y = (2 * oldX + 3 * y) % 5;
        }
        return A;
    }

    static StateArray pi(const StateArray &state)
    {
        /* de acordo com Keccak Reference 2.3.3 */
        auto A = state;
        for (auto x = 0u; x < 5u; ++x) {
            for (auto y = 0u; y < 5u; ++y) {
                A[lane_xy(x, y)] = state[lane_xy((x + 3 * y) % 5, x)];
            }
        }
        return A;
    }

    static StateArray chi(const StateArray &state)
    {
        /* de acordo com Keccak Reference 2.3.1 */
        auto A = state;
        for (auto x = 0u; x < 5u; ++x) {
            for (auto y = 0u; y < 5u; ++y) {
                auto p1 = compl state[lane_xy((x + 1) % 5, y)];
                auto p2 = state[lane_xy((x + 2) % 5, y)];
                A[lane_xy(x, y)] = A[lane_xy(x, y)] xor p1 & p2;
            }
        }
        return A;
    }

    static StateArray iota(const StateArray &state, uint32_t &lfsr)
    {
        /* de acordo com Keccak Reference 2.3.5 */
        auto A = state;
        for (auto i = 0u; i < 7u; ++i) {
            if (lfsr & 1) {
                // bit 2^i - 1
                A[lane_xy(0, 0)] ^= 1ull << ((1u << i) - 1u);
            }
            lfsr = ((lfsr << 1) xor ((lfsr >> 7) * 0x71)) % 256u;
        }
        return A;
    }

    void step_mappings()
    {
        auto lfsr = 1u;
        for (auto i = 0u; i < 24u; ++i) {
            state = iota(chi(pi(rho(theta(state)))), lfsr);
        }
    }

    void squeeze_more()
    {
        step_mappings();
        auto amt = 0u;

        for (auto y = 0u; y < 5u; ++y) {
            for (auto x = 0u; x < 5u; ++x) {
                auto lane = state[lane_xy(x, y)];
                for (auto z = 0u; z < 64u; z += 8u) {
                    output << (char) (lane >> z);

                    ++amt;
                    if (amt == rateInBytes) {
                        npos += rateInBytes;
                        return;
                    }
                }
            }
        }
    }

    StateArray state{};
    size_t npos{0};
    std::stringstream output{};
    enum Phase
    {
        ABSORBING,
        SQUEEZING,
    } phase{ABSORBING};
};

}

template<size_t capacity, size_t digest_length = capacity / 16u>
class SHA3
{
public:
    static std::string hash(const std::string &message)
    {
        detail::Keccak<capacity> keccak;
        keccak.absorb(message);
        keccak.pad("\x06");
        return keccak.squeeze(digest_length);
    }
};

template<size_t capacity>
class SHAKE
{
public:
    void update(const std::string &message)
    {
        keccak.absorb(message);
    }

    void finalize()
    {
        keccak.pad("\x1F");
    }

    std::string digest(size_t length)
    {
        return keccak.squeeze(length);
    }

private:
    detail::Keccak<capacity> keccak;
};

using SHA3_224 = SHA3<448u, 28u>;
using SHA3_256 = SHA3<512u, 32u>;
using SHA3_384 = SHA3<768u, 48u>;
using SHA3_512 = SHA3<1024u, 64u>;
using SHAKE_128 = SHAKE<128u>;
using SHAKE_256 = SHAKE<256u>;

#endif //SHA3_KECCAK_H
