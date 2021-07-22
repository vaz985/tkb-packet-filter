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

#include <proxygen/httpserver/samples/hq/tkb_obs.h>

namespace quic {
namespace samples {

// Observer implementation for testing
void TKBFilterObserver::packetsWritten(QuicSocket * /* socket */,
                                       const AppLimitedEvent &appLimitedEvent) {
  for (auto &filter : filters) {
    filter.processSentPackets(appLimitedEvent.outstandingPackets);
  }
}

void TKBFilterObserver::packetsRemoved(
    QuicSocket *, /* socket */
    const std::shared_ptr<std::vector<OutstandingPacket>> removedPackets) {
  for (auto &filter : filters) {
    filter.processRemovedPackets(removedPackets);
  }
}

void TKBFilterObserver::destroy(QuicSocket * /* socket */) noexcept {
  LOG(INFO) << "Destroy";
  for (auto &filter : filters) {
    LOG(INFO) << filter.linkRateMbps << "mbps " << filter.linkBufferPackets
              << "pkts";
    LOG(INFO) << "Model DR " << filter.getModelDropRate();
    LOG(INFO) << "Remaning Packets " << filter.modelPacketsWritten.size();
    for (auto &packet : filter.modelPacketsWritten) {
      LOG(INFO) << packet.first << " " << packet.second;
    }
  }
}

} // namespace samples
} // namespace quic