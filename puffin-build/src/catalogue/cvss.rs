//! CVSS scores of catalogue entries.
//!
//! One source and one rule for every entry: the CVSS v3.1 base score of NVD (nvd.nist.gov), NIST's
//! primary assessment, or, when NIST gives none, the v3.1 assessment of the CNA shown on NVD
//! (`source = "cna:<name>"`). Never a v2 or v4.0 score. The vector is stored with the score, and
//! the score must be the one the vector gives (FIRST's CVSS v3.1 specification, section 7), so a
//! typo in either is caught.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cvss {
    pub version: String,
    pub score: f64,
    pub vector: String,
    pub source: String,
}

impl Cvss {
    pub fn check(&self) -> Result<(), String> {
        if self.version != "3.1" {
            return Err(format!(
                "CVSS version '{}': only CVSS v3.1 base scores are recorded",
                self.version
            ));
        }

        if !(self.source == "nvd"
            || self
                .source
                .strip_prefix("cna:")
                .is_some_and(|name| !name.trim().is_empty()))
        {
            return Err(format!(
                "CVSS source '{}': expected \"nvd\" (NIST's assessment) or \"cna:<name>\"",
                self.source
            ));
        }

        let computed = base_score_v31(&self.vector)?;
        if (computed - self.score).abs() > 1e-9 {
            return Err(format!(
                "CVSS score {} does not match its vector {} (base score {computed})",
                self.score, self.vector
            ));
        }

        Ok(())
    }
}

/// The CVSS v3.1 base score of a base vector (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` gives
/// 7.5).
pub fn base_score_v31(vector: &str) -> Result<f64, String> {
    let metrics = vector
        .strip_prefix("CVSS:3.1/")
        .ok_or_else(|| format!("CVSS vector '{vector}' does not start with 'CVSS:3.1/'"))?;

    let mut values: [Option<&str>; 8] = [None; 8];
    const NAMES: [&str; 8] = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"];

    for metric in metrics.split('/') {
        let (name, value) = metric
            .split_once(':')
            .ok_or_else(|| format!("CVSS vector '{vector}': invalid metric '{metric}'"))?;
        let index = NAMES.iter().position(|n| *n == name).ok_or_else(|| {
            format!("CVSS vector '{vector}': '{name}' is not a base metric (only base vectors are recorded)")
        })?;
        if values[index].replace(value).is_some() {
            return Err(format!(
                "CVSS vector '{vector}': metric '{name}' given twice"
            ));
        }
    }

    let get = |i: usize| {
        values[i].ok_or_else(|| format!("CVSS vector '{vector}': missing metric '{}'", NAMES[i]))
    };
    let invalid = |i: usize, v: &str| {
        format!(
            "CVSS vector '{vector}': invalid value '{v}' for '{}'",
            NAMES[i]
        )
    };

    let scope_changed = match get(4)? {
        "U" => false,
        "C" => true,
        v => return Err(invalid(4, v)),
    };
    let av = match get(0)? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        v => return Err(invalid(0, v)),
    };
    let ac = match get(1)? {
        "L" => 0.77,
        "H" => 0.44,
        v => return Err(invalid(1, v)),
    };
    let pr = match (get(2)?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        (v, _) => return Err(invalid(2, v)),
    };
    let ui = match get(3)? {
        "N" => 0.85,
        "R" => 0.62,
        v => return Err(invalid(3, v)),
    };
    let cia = |i: usize| -> Result<f64, String> {
        match get(i)? {
            "H" => Ok(0.56),
            "L" => Ok(0.22),
            "N" => Ok(0.0),
            v => Err(invalid(i, v)),
        }
    };
    let (c, i, a) = (cia(5)?, cia(6)?, cia(7)?);

    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    let exploitability = 8.22 * av * ac * pr * ui;

    if impact <= 0.0 {
        return Ok(0.0);
    }

    Ok(if scope_changed {
        roundup(f64::min(1.08 * (impact + exploitability), 10.0))
    } else {
        roundup(f64::min(impact + exploitability, 10.0))
    })
}

/// `Roundup` of the CVSS v3.1 specification (Appendix A): the smallest number with one decimal that
/// is equal to or higher than its input, computed on integers to avoid floating-point artifacts.
fn roundup(input: f64) -> f64 {
    let int_input = (input * 100_000.0).round() as i64;
    if int_input % 10_000 == 0 {
        int_input as f64 / 100_000.0
    } else {
        ((int_input / 10_000) + 1) as f64 / 10.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_scores_match_nvd() {
        // vectors and scores as published by NVD
        for (vector, score) in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5), // CVE-2022-39173
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N", 6.5), // CVE-2022-25638
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N", 7.5), // CVE-2022-25640
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H", 5.9), // CVE-2022-38153
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H", 9.1), // CVE-2022-42905
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3), // CVE-2024-5814
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5), // CVE-2014-0160
            ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.1), // CVE-2021-3336
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ] {
            assert_eq!(base_score_v31(vector), Ok(score), "{vector}");
        }
    }

    #[test]
    fn invalid_vectors_are_refused() {
        for bad in [
            "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/A:H",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P",
        ] {
            assert!(base_score_v31(bad).is_err(), "{bad} accepted");
        }
    }

    #[test]
    fn check_refuses_a_score_that_does_not_match_its_vector() {
        let mut cvss = Cvss {
            version: "3.1".into(),
            score: 7.5,
            vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H".into(),
            source: "nvd".into(),
        };
        assert_eq!(cvss.check(), Ok(()));

        cvss.score = 7.4;
        assert!(cvss.check().unwrap_err().contains("does not match"));

        cvss.score = 7.5;
        cvss.source = "somewhere".into();
        assert!(cvss.check().is_err());

        cvss.source = "cna:wolfSSL".into();
        cvss.version = "3.0".into();
        assert!(cvss.check().is_err());
    }
}
