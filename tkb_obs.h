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

#include <quic/api/Observer.h>

#include <proxygen/httpserver/samples/hq/tkb.h>

namespace quic {
namespace samples {

// Observer implementation for testing
class TKBFilterObserver : public Observer {
public:
  TimePoint lastTxTime{Clock::now()};
  std::vector<TokenBucketFilter> filters;

  TKBFilterObserver(Observer::Config &cfg) : Observer(cfg) {}

  ~TKBFilterObserver() { filters.clear(); };

  void emplaceFilter(uint64_t linkRateMbpsIn, uint64_t linkBufferPacketsIn,
                     uint64_t linkMTUIn) {
    filters.emplace_back(linkRateMbpsIn, linkBufferPacketsIn, linkMTUIn);
  };

  void packetsWritten(QuicSocket * /* socket */,
                      const AppLimitedEvent &appLimitedEvent) override;

  void packetsRemoved(QuicSocket * /* socket */,
                      const std::shared_ptr<std::vector<OutstandingPacket>>
                          removedPackets) override;

  void destroy(QuicSocket * /* socket */) noexcept override;
};

} // namespace samples
} // namespace quic