/*  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  Artur Vaz <arturvaz@dcc.ufmg.br>, 2021
 */

#pragma once

#include <chrono>
#include <cmath>
#include <set>

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/state/OutstandingPacket.h>

#include <folly/Hash.h>

constexpr uint64_t kTokenBucketThresholdPackets = 4;

std::string pnSpaceStr(quic::PacketNumberSpace val);

typedef std::pair<std::string, uint64_t> packetId;

struct PacketInfo {
  quic::TimePoint time;
  quic::PacketNumberSpace packetNumberSpace;
  quic::PacketNum packetNum;

  PacketInfo(const quic::OutstandingPacket &outstandingPacket)
      : time(outstandingPacket.metadata.time),
        packetNumberSpace(
            outstandingPacket.packet.header.getPacketNumberSpace()),
        packetNum(outstandingPacket.packet.header.getPacketSequenceNum()) {}

  // for sorting
  bool operator<(const PacketInfo &other) const { return time < other.time; }

  packetId getId() {
    return packetId(pnSpaceStr(packetNumberSpace), (uint64_t)packetNum);
  }
};

class TokenBucketFilter {
public:
  uint64_t linkRateMbps;
  uint64_t linkBufferPackets;
  uint64_t linkMTU;
  uint64_t bucketTokens;
  std::chrono::microseconds tokenCost;
  quic::TimePoint lastTxTime{quic::Clock::now().min()};
  quic::TimePoint bucketTime{quic::Clock::now().max()};

  TokenBucketFilter(uint64_t linkRateMbpsIn = 10,
                    uint64_t linkBufferPacketsIn = 20,
                    uint64_t linkMTUIn = 1500)
      : linkRateMbps(linkRateMbpsIn), linkBufferPackets(linkBufferPacketsIn),
        linkMTU(linkMTUIn), bucketTokens(linkBufferPacketsIn),
        tokenCost((linkMTUIn * 8) / (linkRateMbpsIn)) {}

  std::unordered_set<packetId> modelPacketsWritten;

  ~TokenBucketFilter() { modelPacketsWritten.clear(); }

  uint64_t modelLost{0};
  uint64_t modelNotLost{0};

  long double getModelDropRate() {
    return (modelNotLost > 0)
               ? ((long double)modelLost / (long double)modelNotLost)
               : 0;
  }

  void
  processSentPackets(const std::deque<quic::OutstandingPacket> &sentPackets);
  void processRemovedPackets(
      const std::shared_ptr<std::vector<quic::OutstandingPacket>>
          removedPackets);
};
