use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ThreatLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ThreatLevel::None     => "NONE",
            ThreatLevel::Low      => "LOW",
            ThreatLevel::Medium   => "MEDIUM",
            ThreatLevel::High     => "HIGH",
            ThreatLevel::Critical => "CRITICAL",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ThreatFlag {
    pub level:       ThreatLevel,
    pub code:        String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntryInfo {
    pub name:               String,
    pub compressed_size:    u32,
    pub uncompressed_size:  u32,
    pub ratio:              f64,
    pub method:             u16,
    pub local_offset:       u32,
    pub is_nested_archive:  bool,
}

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub path:               String,
    pub is_threat:          bool,
    pub threat_level:       ThreatLevel,
    pub entry_count:        u32,
    pub total_compressed:   u64,
    pub total_uncompressed: u64,
    pub overall_ratio:      f64,
    pub nesting_depth:      u32,
    pub has_overlaps:       bool,
    pub scan_us:            u128,
    pub flags:              Vec<ThreatFlag>,
    pub entries:            Vec<EntryInfo>,
}

impl ScanResult {
    pub fn new(path: String, depth: u32) -> Self {
        Self {
            path,
            is_threat:          false,
            threat_level:       ThreatLevel::None,
            entry_count:        0,
            total_compressed:   0,
            total_uncompressed: 0,
            overall_ratio:      0.0,
            nesting_depth:      depth,
            has_overlaps:       false,
            scan_us:            0,
            flags:              Vec::new(),
            entries:            Vec::new(),
        }
    }

    pub fn add_flag(&mut self, level: ThreatLevel, code: &str, desc: String) {
        if level > self.threat_level {
            self.threat_level = level.clone();
        }
        self.is_threat = self.threat_level > ThreatLevel::None;
        self.flags.push(ThreatFlag { level, code: code.to_string(), description: desc });
    }

    pub fn print_summary(&self) {
        println!("  File      : {}", self.path);
        println!("  Threat    : {}", self.threat_level);
        println!("  Entries   : {}", self.entry_count);
        println!("  Compressed: {} bytes", self.total_compressed);
        println!("  Expanded  : {} bytes", self.total_uncompressed);
        println!("  Ratio     : {:.2} : 1", self.overall_ratio);
        println!("  Overlaps  : {}", if self.has_overlaps { "YES" } else { "No" });
        println!("  Depth     : {}", self.nesting_depth);
        println!("  Scan µs   : {}", self.scan_us);
        for f in &self.flags {
            println!("  [{}] {}: {}", f.level, f.code, f.description);
        }
        println!();
    }
}
