#pragma once

#include <algorithm>
#include <cstddef>
#include <vector>

namespace sifrprobe {

struct Percentiles {
    double min;
    double p50;
    double p90;
    double p99;
    double max;
    double mean;
};

// Keep the original nearest-order-statistic definition: round(q * (n - 1)).
inline Percentiles summarize(const std::vector<double>& values) {
    if (values.empty()) return {0.0, 0.0, 0.0, 0.0, 0.0, 0.0};

    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    double sum = 0.0;
    for (double value : sorted) sum += value;

    auto at = [&](double quantile) {
        const auto last = static_cast<double>(sorted.size() - 1);
        const auto index = static_cast<std::size_t>(quantile * last + 0.5);
        return sorted[index];
    };
    const auto size = static_cast<double>(sorted.size());
    return {sorted.front(), at(0.50), at(0.90), at(0.99), sorted.back(), sum / size};
}

}  // namespace sifrprobe
