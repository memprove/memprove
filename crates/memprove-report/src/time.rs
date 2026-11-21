//! Timestamps as the clients write them (`2026-11-17T02:37:47.001Z`, with
//! or without the fraction) to milliseconds since 1970, and back to the
//! minute for a person.

/// Milliseconds since 1970-01-01T00:00:00Z of an RFC 3339 UTC timestamp
/// (`Z` only), or `None` when `text` is not one.
#[must_use]
pub fn unix_ms(text: &str) -> Option<i64> {
    let text = text.strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let (clock, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut clock_parts = clock.split(':');
    let hour: i64 = clock_parts.next()?.parse().ok()?;
    let minute: i64 = clock_parts.next()?.parse().ok()?;
    let second: i64 = clock_parts.next()?.parse().ok()?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let millis: i64 = fraction
        .chars()
        .chain("000".chars())
        .take(3)
        .collect::<String>()
        .parse()
        .ok()?;
    let days = days_from_civil(year, month, day);
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis)
}

/// `ms` as `YYYY-MM-DD HH:MM` (UTC).
#[must_use]
pub fn minute(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rest = ms.rem_euclid(86_400_000) / 60_000;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}",
        rest / 60,
        rest % 60
    )
}

/// `ms` as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn iso(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rest = ms.rem_euclid(86_400_000);
    let (year, month, day) = civil_from_days(days);
    let seconds = rest / 1000;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60,
        rest % 1000
    )
}

/// `ms` as `HH:MM:SS` (UTC).
#[must_use]
pub fn clock(ms: i64) -> String {
    let rest = ms.rem_euclid(86_400_000) / 1000;
    format!("{:02}:{:02}:{:02}", rest / 3600, rest / 60 % 60, rest % 60)
}

/// A duration in milliseconds in words: `45 s`, `33 min`, `2 h 05 min`.
#[must_use]
pub fn duration(ms: i64) -> String {
    let seconds = ms.max(0) / 1000;
    if seconds < 60 {
        format!("{seconds} s")
    } else if seconds < 3600 {
        format!("{} min", seconds / 60)
    } else {
        format!("{} h {:02} min", seconds / 3600, seconds / 60 % 60)
    }
}

/// Howard Hinnant's `days_from_civil`: a proleptic Gregorian date to days
/// since 1970-01-01.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year.rem_euclid(400);
    let month = i64::from(month);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Howard Hinnant's `civil_from_days`.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = u32::try_from(doy - (153 * mp + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if mp < 10 { mp + 3 } else { mp - 9 }).unwrap_or(1);
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_round_trip_to_the_minute() {
        let ms = unix_ms("2026-11-17T02:37:47.001Z").unwrap();
        assert_eq!(ms % 1000, 1);
        assert_eq!(minute(ms), "2026-11-17 02:37");
        assert_eq!(clock(ms), "02:37:47");
        assert_eq!(iso(ms), "2026-11-17T02:37:47.001Z");
        assert_eq!(unix_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(unix_ms("2024-02-29T12:00:00.5Z"), Some(1_709_208_000_500));
        assert_eq!(unix_ms("2026-11-17T02:37:47+00:00"), None);
        assert_eq!(unix_ms("2026-13-01T00:00:00Z"), None);
        assert_eq!(unix_ms("2026-11-17T02:37:47.0x1Z"), None);
    }

    #[test]
    fn durations_read_as_words() {
        assert_eq!(duration(45_000), "45 s");
        assert_eq!(duration(33 * 60_000 + 5_000), "33 min");
        assert_eq!(duration(2 * 3_600_000 + 5 * 60_000), "2 h 05 min");
        assert_eq!(duration(-5), "0 s");
    }
}
