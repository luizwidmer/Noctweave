import Foundation

public enum MetadataMinimizer {
    public static func bucketedTimestamp(
        _ timestamp: Date,
        bucketSeconds: Int?
    ) -> Date {
        guard let bucketSeconds, bucketSeconds > 1 else {
            return timestamp
        }
        let interval = timestamp.timeIntervalSince1970
        let bucket = TimeInterval(bucketSeconds)
        let bucketed = floor(interval / bucket) * bucket
        return Date(timeIntervalSince1970: bucketed)
    }
}
