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

#include <proxygen/httpserver/samples/hq/tkb.h>

std::string pnSpaceStr(quic::PacketNumberSpace pnSpace) {
  switch (pnSpace) {
  case quic::PacketNumberSpace::Initial:
    return "IN";
    break;
  case quic::PacketNumberSpace::Handshake:
    return "HS";
    break;
  case quic::PacketNumberSpace::AppData:
    return "AD";
    break;
  default:
    return "NULL";
    break;
  }
}

void TokenBucketFilter::processSentPackets(
    const std::deque<quic::OutstandingPacket> &outstandingQueue) {

  // Only some of the packets at the outstandingQueue were written,
  // we control this by maintaining the timestamp of the last sent packet.
  std::vector<PacketInfo> orderedSentPackets;
  auto packetIt = std::lower_bound(
      outstandingQueue.begin(), outstandingQueue.end(), lastTxTime,
      [](const quic::OutstandingPacket &packet, quic::TimePoint time) {
        return packet.metadata.time < time;
      });
  while (packetIt != outstandingQueue.end()) {
    auto packet = *packetIt;
    orderedSentPackets.emplace_back(packet);
    lastTxTime = packet.metadata.time;
    packetIt++;
  }

  for (auto &packet : orderedSentPackets) {
    quic::TimePoint packetTime = packet.time;
    // Fixing the MTU enable us to fast compute the drained packets at the cost
    // of overestimating the time packets spent on the queue
    if ((bucketTime + tokenCost) < packetTime) {
      uint64_t packetsDrained = (packetTime - bucketTime) / tokenCost;
      bucketTime += (tokenCost * packetsDrained);
      bucketTokens = std::min(bucketTokens + packetsDrained, linkBufferPackets);
    }
    // We only track packets when we have over kTokenBucketThresholdPackets
    // tokens
    bool predictLost = bucketTokens <= kTokenBucketThresholdPackets;
    if (!predictLost) {
      modelPacketsWritten.emplace(packet.getId());
    }
    if (bucketTokens > 0) {
      if (bucketTokens == linkBufferPackets) {
        bucketTime = packetTime;
      }
      bucketTokens--;
    } else {
      // This delay the recovery of tokens to avoid suddenly recoveries of
      // tokens when losses are happening
      bucketTime = packetTime;
    }
  }
};

void TokenBucketFilter::processRemovedPackets(
    const std::shared_ptr<std::vector<quic::OutstandingPacket>>
        removedPackets) {
  auto packetIt = removedPackets->begin();
  while (packetIt != removedPackets->end()) {
    auto removedPacket = *packetIt;
    auto inFlightPacket =
        modelPacketsWritten.find(PacketInfo(removedPacket).getId());
    if (inFlightPacket != modelPacketsWritten.end()) {
      modelPacketsWritten.erase(inFlightPacket);
      if (packetIt->declaredLost) {
        modelLost++;
      } else {
        modelNotLost++;
      }
    }
    packetIt++;
  }
};