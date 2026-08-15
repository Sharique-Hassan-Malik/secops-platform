/// Configurable detection thresholds.
#[derive(Debug, Clone)]
pub struct ScanPolicy {
    pub max_ratio:         f64,
    pub max_uncompressed:  u64,
    pub max_entries:       u32,
    pub max_nesting_depth: u32,
    pub check_overlaps:    bool,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            max_ratio:         100.0,
            max_uncompressed:  4 * 1024 * 1024 * 1024,
            max_entries:       10_000,
            max_nesting_depth: 3,
            check_overlaps:    true,
        }
    }
}

impl ScanPolicy {
    pub fn strict() -> Self {
        Self { max_ratio: 50.0, max_uncompressed: 1 << 30, max_entries: 500, max_nesting_depth: 2, check_overlaps: true }
    }
    pub fn paranoid() -> Self {
        Self { max_ratio: 10.0, max_uncompressed: 1 << 28, max_entries: 100, max_nesting_depth: 1, check_overlaps: true }
    }
    pub fn relaxed() -> Self {
        Self { max_ratio: 500.0, max_uncompressed: 1 << 36, max_entries: 50_000, max_nesting_depth: 5, check_overlaps: true }
    }
}
