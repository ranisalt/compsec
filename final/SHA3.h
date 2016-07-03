#ifndef SHA3_KECCAK_H
#define SHA3_KECCAK_H

#include <array> /* std::array */
#include <cstdint> /* std::size_t, std::uint64_t */
#include <string> /* std::string */

template<class T>
constexpr T rotate_left(T i, std::size_t shamt) {
    auto width = (sizeof i) * 8u;
    return (i << shamt) ^ (i >> (width - shamt));
}

template<std::size_t capacity, std::size_t digest_length = capacity / 16u>
class SHA3 {
    static_assert(capacity % 16 == 0, "Capacity must be multiple of 16.");

    static constexpr std::size_t rate = 1600u - capacity;

    // lane = 64 bits
    using lane = std::uint64_t;

    // 5 columns x 5 rows x 64 bits
    using StateArray = std::array<lane, 5 * 5>;

    // round constant generator
    class LFSR {
    public:
        bool operator()() {
            auto ret = state & 1;
            if (state & 0x80) {
                state = (state << 1) & 0b1110001;
            } else {
                state <<= 1;
            }
            return ret != 0;
        }

    private:
        uint64_t state = 1;
    };

public:
    SHA3() = default;

    std::string hash(const std::string &message) {
        auto state = absorb(message, 0x01);
    }

private:
    // calcula posição da lane (x, y) no state array
    constexpr std::size_t lane_xy(std::size_t x, std::size_t y) const {
        return x + 5 * y;
    }

    constexpr std::uint64_t round_constant(std::size_t round) const {

    }

    StateArray theta(const StateArray &state) const {
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
            auto D = C[(i + 4) % 5] xor rotate_left(C[(i + 1) % 5], 1);
            for (auto j = 0u; j < 5u; ++j) {
                A[lane_xy(i, j)] ^= D;
            }
        }

        return A;
    }

    StateArray rho(const StateArray &state) const {
        /* de acordo com Keccak Reference 2.3.4 */
        auto A = state;
        auto x = 1u, y = 0u;
        for (auto t = 0u; t < 24; ++t) {
            auto shamt = ((t + 1) * (t + 2)) / 2;
            A[lane_xy(x, y)] = rotate_left(state[lane_xy(x, y)], shamt);

        }
    }

    StateArray pi(const StateArray &state) const {
        /* de acordo com Keccak Reference 2.3.3 */
        auto A = state;
        for (auto x = 0u; x < 5u; ++x) {
            for (auto y = 0u; y < 5u; ++y) {
                A[lane_xy(y, (2 * x + 3 * y) % 5)] = state[lane_xy(x, y)];
                auto oldX = x;
                x = y;
                y = 2 * oldX + 3 * y;
            }
        }
        return A;
    }

    StateArray chi(const StateArray &state) const {
        /* de acordo com Keccak Reference 2.3.1 */
        auto A = state;
        for (auto x = 0u; x < 5u; ++x) {
            for (auto y = 0u; y < 5u; ++y) {
                auto p1 = compl state[lane_xy((x + 1) % 5, y)];
                auto p2 = state[lane_xy((x + 2) % 5, y)];
                A[lane_xy(x, y)] ^= p1 bitand p2;
            }
        }
        return A;
    }

    StateArray iota(const StateArray &state, LFSR &lfsr) const {
        /* de acordo com Keccak Reference 2.3.5 */
        auto A = state;
        for (auto i = 0u; i < 7u; ++i) {
            if (lfsr()) {
                // 2^i - 1
                A[0, 0] ^= (lane) 1u << ((1u << i) - 1u);
            }
        }
        return A;
    }

    StateArray step_mappings(const StateArray &state) const {
        auto A = state;
        auto lfsr = LFSR{};
        for (auto i = 0u; i < 24u; ++i) {
            A = iota(chi(pi(rho(theta(A)))), lfsr);
        }
        return A;
    }

    StateArray absorb(const std::string &input, uint8_t suffix) {
        constexpr auto rateInBytes = rate / 8u;

        StateArray state;
        StateArray::size_type idx = 0;

        for (const auto &ch: input) {
            state[idx] ^= ch;

            ++idx;
            if (idx == rateInBytes) {
                state = step_mappings(state);
                idx = 0u;
            }
        }

        state[idx] ^= suffix;

        /* TODO: pad10*1 */

        return state;
    }
};

#endif //SHA3_KECCAK_H
