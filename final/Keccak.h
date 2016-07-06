#ifndef SHA3_KECCAK_H
#define SHA3_KECCAK_H

#include <stdint.h> /* size_t, uint8_t, uint64_t */
#include <array> /* std::array */
#include <sstream> /* std::stringstream */
#include <string> /* std::string */

template<class T>
constexpr T rot_left(T i, size_t shamt) {
    return (i << shamt) ^ (i >> (((sizeof i) * 8u) - shamt));
}

template<size_t capacity>
class Keccak {
    static_assert(capacity % 16 == 0, "Capacity must be 16k.");

    static constexpr auto rate = 1600u - capacity;
    static constexpr auto rateInBytes = rate / 8u;

    using lane = uint64_t; // lane = 64 bits
    using StateArray = std::array<lane, 5*5>; // 5 col x 5 row x 64 b

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
    Keccak() = default;

    Keccak& update(const std::string &message) {
        if (phase != ABSORBING) {
            throw std::logic_error("Must not absorb after squeezing");
        }
        absorb(message);
        return *this;
    }

    std::string digest(size_t digest_length = capacity / 16u) {
        if (phase == ABSORBING) {
            pad("\x01");
        }
        return squeeze(digest_length);
    }

private:
    // calcula posição da lane (x, y) no state array
    static constexpr size_t lane_xy(size_t x, size_t y) {
        return x + 5*y;
    }

    static StateArray theta(const StateArray &state) {
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

    static StateArray rho(const StateArray &state) {
        /* de acordo com Keccak Reference 2.3.4 */
        auto A = state;
        auto x = 1u, y = 0u;
        for (auto t = 0u; t < 24; ++t) {
            auto shamt = ((t+1) * (t+2)) / 2;
            A[lane_xy(x, y)] = rot_left(state[lane_xy(x, y)], shamt % 64);
            auto oldX = x;
            x = y % 5;
            y = (2*oldX + 3*y) % 5;
        }
        return state;
    }

    static StateArray pi(const StateArray &state) {
        /* de acordo com Keccak Reference 2.3.3 */
        auto A = state;
        for (auto x = 0u; x < 5u; ++x) {
            for (auto y = 0u; y < 5u; ++y) {
                A[lane_xy(y, (2*x + 3*y) % 5)] = state[lane_xy(x, y)];
            }
        }
        return A;
    }

    static StateArray chi(const StateArray &state) {
        /* de acordo com Keccak Reference 2.3.1 */
        auto A = state;
        for (auto x = 0u; x < 5u; ++x) {
            for (auto y = 0u; y < 5u; ++y) {
                auto p1 = compl state[lane_xy((x+1) % 5, y)];
                auto p2 = state[lane_xy((x+2) % 5, y)];
                A[lane_xy(x, y)] ^= p1 bitand p2;
            }
        }
        return A;
    }

    static StateArray iota(const StateArray &state, LFSR &lfsr) {
        /* de acordo com Keccak Reference 2.3.5 */
        auto A = state;
        for (auto i = 0u; i < 7u; ++i) {
            if (lfsr()) {
                // bit 2^i - 1
                A[lane_xy(0, 0)] ^= (lane) 1u << ((1u << i) - 1u);
            }
        }
        return A;
    }

    static StateArray step_mappings(const StateArray &state) {
        auto A = state;
        auto lfsr = LFSR{};
        for (auto i = 0u; i < 24u; ++i) {
            A = iota(chi(pi(rho(theta(A)))), lfsr);
        }
        return A;
    }

    void absorb(const std::string &input) {
        for (const auto &ch: input) {
            auto laneNo = npos / 8u;
            auto offset = npos % 8u;
            state[laneNo] ^= (lane)static_cast<uint8_t>(ch) << (offset * 8u);

            ++npos;
            if (npos == rateInBytes) {
                state = step_mappings(state);
                npos = 0u;
            }
        }
    }

    void pad(const std::string &suffix) {
        auto q = rateInBytes - npos;
        auto laneNo = npos / 8u;
        auto offset = npos % 8u;
        state[laneNo] ^= (lane)0x06u << (offset * 8u);

        laneNo = (rateInBytes-1) / 8u;
        offset = (rateInBytes-1) % 8u;
        state[laneNo] ^= (lane)0x80u << (offset * 8u);

        npos = 0u;
        state = step_mappings(state);
        phase = SQUEEZING;
    }

    std::string squeeze(size_t length) {
        std::stringstream ss;
        ss << std::hex;

        auto amt = 0u;
        while (amt < length) {
            for (auto x = 0u; x < 5u; ++x) {
                for (auto y = 0u; y < 5u; ++y) {
                    auto lane = state[lane_xy(x, y)];
                    for (auto z = sizeof lane; z > 0u; --z) {
                        ss << (char) (lane >> (z - 1) * 8u);

                        ++npos;
                        if (npos == rateInBytes) {
                            state = step_mappings(state);
                            npos = 0u;
                        }

                        ++amt;
                        if (amt == length) {
                            return ss.str();
                        }
                    }
                }
            }
            state = step_mappings(state);
        }

        return ss.str();
    }

    StateArray state;
    StateArray::size_type npos = 0;
    enum Phase {
        ABSORBING,
        SQUEEZING,
    } phase;
};

using SHA3_224 = Keccak<448u>;
using SHA3_256 = Keccak<512u>;
using SHA3_384 = Keccak<768u>;
using SHA3_512 = Keccak<1024u>;

#endif //SHA3_KECCAK_H
