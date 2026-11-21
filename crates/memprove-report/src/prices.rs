//! What tokens cost at list prices: a built-in table of Anthropic's API
//! prices and a price file for any other model. Prices are kept as
//! thousandths of a US dollar per million tokens, so that a cost is a whole
//! number of billionths of a dollar and no float is needed.

use std::{collections::BTreeMap, fs, path::Path};

use crate::model::{Bucket, Usage};

/// Where the built-in prices come from, and when they were read.
pub const BUILT_IN_SOURCE: &str =
    "Anthropic API list prices, platform.claude.com/docs/en/about-claude/pricing, read 2026-11-17";

/// The prompt length above which Claude Haiku 5.5 bills a request at its
/// higher prices.
pub const LONG_PROMPT_TOKENS: u64 = 100_000;

/// One model's prices, in thousandths of a US dollar per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    /// Input tokens.
    pub input: u64,
    /// Five-minute cache writes.
    pub cache_write: u64,
    /// One-hour cache writes.
    pub cache_write_1h: u64,
    /// Cache reads.
    pub cache_read: u64,
    /// Output tokens.
    pub output: u64,
}

impl Price {
    const fn new(
        input: u64,
        cache_write: u64,
        cache_write_1h: u64,
        cache_read: u64,
        output: u64,
    ) -> Self {
        Self {
            input,
            cache_write,
            cache_write_1h,
            cache_read,
            output,
        }
    }

    /// The cost of `usage` at these prices, in billionths of a US dollar.
    #[must_use]
    pub fn cost_nano(&self, usage: &Usage) -> u128 {
        let at = |tokens: u64, price: u64| u128::from(tokens) * u128::from(price);
        at(usage.input, self.input)
            + at(usage.cache_write, self.cache_write)
            + at(usage.cache_write_1h, self.cache_write_1h)
            + at(usage.cache_read, self.cache_read)
            + at(usage.output, self.output)
    }
}

/// Anthropic's models: their names after [`normalize`], their prices, and
/// (Claude Haiku 5.5) their prices for prompts over [`LONG_PROMPT_TOKENS`].
const CLAUDE: &[(&str, Price, Option<Price>)] = &[
    (
        "claude-fable-5-2",
        Price::new(8000, 10000, 16000, 200, 40000),
        None,
    ),
    (
        "claude-mythos-5-2",
        Price::new(8000, 10000, 16000, 200, 40000),
        None,
    ),
    (
        "claude-fable-5-1",
        Price::new(10000, 12500, 20000, 250, 50000),
        None,
    ),
    (
        "claude-mythos-5-1",
        Price::new(10000, 12500, 20000, 250, 50000),
        None,
    ),
    (
        "claude-fable-5",
        Price::new(10000, 12500, 20000, 1000, 50000),
        None,
    ),
    (
        "claude-mythos-5",
        Price::new(10000, 12500, 20000, 1000, 50000),
        None,
    ),
    (
        "claude-opus-5-5",
        Price::new(4000, 5000, 8000, 200, 20000),
        None,
    ),
    (
        "claude-opus-5",
        Price::new(5000, 6250, 10000, 500, 25000),
        None,
    ),
    (
        "claude-opus-4-8",
        Price::new(5000, 6250, 10000, 500, 25000),
        None,
    ),
    (
        "claude-opus-4-7",
        Price::new(5000, 6250, 10000, 500, 25000),
        None,
    ),
    (
        "claude-opus-4-6",
        Price::new(5000, 6250, 10000, 500, 25000),
        None,
    ),
    (
        "claude-opus-4-5",
        Price::new(5000, 6250, 10000, 500, 25000),
        None,
    ),
    (
        "claude-opus-4-1",
        Price::new(15000, 18750, 30000, 1500, 75000),
        None,
    ),
    (
        "claude-opus-4",
        Price::new(15000, 18750, 30000, 1500, 75000),
        None,
    ),
    (
        "claude-sonnet-5-5",
        Price::new(2000, 2500, 4000, 100, 10000),
        None,
    ),
    (
        "claude-sonnet-5",
        Price::new(2000, 2500, 4000, 200, 10000),
        None,
    ),
    (
        "claude-sonnet-4-6",
        Price::new(3000, 3750, 6000, 300, 15000),
        None,
    ),
    (
        "claude-sonnet-4-5",
        Price::new(3000, 3750, 6000, 300, 15000),
        None,
    ),
    (
        "claude-sonnet-4",
        Price::new(3000, 3750, 6000, 300, 15000),
        None,
    ),
    (
        "claude-haiku-5-5",
        Price::new(100, 125, 200, 10, 500),
        Some(Price::new(500, 625, 1000, 50, 2500)),
    ),
    (
        "claude-haiku-4-5",
        Price::new(1000, 1250, 2000, 100, 5000),
        None,
    ),
];

/// Models whose `inference_geo` of `us` costs 1.1 times as much: Claude 4.6
/// and later.
fn us_surcharge(model: &str) -> bool {
    !matches!(
        model,
        "claude-opus-4-5"
            | "claude-opus-4-1"
            | "claude-opus-4"
            | "claude-sonnet-4-5"
            | "claude-sonnet-4"
            | "claude-haiku-4-5"
    )
}

/// A model name as the table names it: from `claude-` on, without a
/// platform's suffix (`@…`, `:…`, `[…]`, `-v1`) or a date (`-20251001`).
/// `None` when the name has no `claude-`.
#[must_use]
pub fn normalize(model: &str) -> Option<String> {
    let start = model.find("claude-")?;
    let mut name = &model[start..];
    if let Some(end) = name.find(['@', ':', '[']) {
        name = &name[..end];
    }
    while let Some((head, last)) = name.rsplit_once('-') {
        let version = last.strip_prefix('v').is_some_and(|digits| {
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
        });
        let date = last.len() == 8 && last.bytes().all(|byte| byte.is_ascii_digit());
        if version || date {
            name = head;
        } else {
            break;
        }
    }
    Some(name.to_owned())
}

/// The prices a report uses: the built-in table and a price file's lines,
/// which come first.
#[derive(Debug, Clone, Default)]
pub struct Prices {
    /// The price file's patterns, in its order.
    file: Vec<(String, Price)>,
}

/// Why a bucket has no cost.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Priced {
    /// Its cost in billionths of a US dollar, and where the price came from.
    Cost(u128, &'static str),
    /// No price is known for the model.
    Unknown,
}

impl Prices {
    /// The prices of the price file at `path` on top of the built-in ones.
    ///
    /// # Errors
    ///
    /// One sentence naming the file and the line that cannot be read.
    pub fn with_file(path: &Path) -> Result<Self, String> {
        let text = fs::read_to_string(path)
            .map_err(|error| format!("{} cannot be read: {error}", path.display()))?;
        Self::parse(&text).map_err(|(line, why)| format!("{}:{line}: {why}", path.display()))
    }

    /// The prices of a price file's `text`: one model per line, `<model or
    /// pattern with *> input=<$/MTok> output=<$/MTok> [cache_read=…]
    /// [cache_write=…] [cache_write_1h=…]`, `#` starting a comment.
    /// `cache_read` and `cache_write` default to `input`, `cache_write_1h`
    /// to `cache_write`.
    ///
    /// # Errors
    ///
    /// The line number and why it cannot be read.
    pub fn parse(text: &str) -> Result<Self, (usize, String)> {
        let mut file = Vec::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let number = index + 1;
            let mut words = line.split_whitespace();
            let pattern = words.next().unwrap_or_default().to_owned();
            let mut values: BTreeMap<&str, u64> = BTreeMap::new();
            for word in words {
                let (name, value) = word
                    .split_once('=')
                    .ok_or_else(|| (number, format!("`{word}` is not name=value")))?;
                if !matches!(
                    name,
                    "input" | "output" | "cache_read" | "cache_write" | "cache_write_1h"
                ) {
                    return Err((number, format!("unknown price `{name}`")));
                }
                let value = milli(value).ok_or_else(|| {
                    (
                        number,
                        format!(
                            "`{value}` is not a price in dollars per million tokens, such as 2.50"
                        ),
                    )
                })?;
                if values.insert(name, value).is_some() {
                    return Err((number, format!("`{name}` is given twice")));
                }
            }
            let (Some(&input), Some(&output)) = (values.get("input"), values.get("output")) else {
                return Err((number, "input= and output= are required".to_owned()));
            };
            let cache_write = values.get("cache_write").copied().unwrap_or(input);
            file.push((
                pattern,
                Price {
                    input,
                    cache_write,
                    cache_write_1h: values.get("cache_write_1h").copied().unwrap_or(cache_write),
                    cache_read: values.get("cache_read").copied().unwrap_or(input),
                    output,
                },
            ));
        }
        Ok(Self { file })
    }

    /// The price of `bucket`'s requests and where it comes from, before
    /// fast mode and data residency.
    fn base(&self, bucket: &Bucket) -> Option<(Price, &'static str, Option<String>)> {
        if let Some((_, price)) = self
            .file
            .iter()
            .find(|(pattern, _)| matches(pattern, &bucket.model))
        {
            return Some((*price, "price file", None));
        }
        let name = normalize(&bucket.model)?;
        let mut key = name.as_str();
        loop {
            if let Some((_, standard, long)) = CLAUDE.iter().find(|(model, _, _)| *model == key) {
                let price = if bucket.long_prompt {
                    long.unwrap_or(*standard)
                } else {
                    *standard
                };
                return Some((price, "built-in", Some(key.to_owned())));
            }
            let (head, last) = key.rsplit_once('-')?;
            if !last.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            key = head;
        }
    }

    /// The cost of `usage` in `bucket`: fast mode doubles a built-in price,
    /// and `inference_geo` `us` multiplies it by 1.1 on Claude 4.6 and
    /// later. A price file's price is taken as it is.
    #[must_use]
    pub fn cost(&self, bucket: &Bucket, usage: &Usage) -> Priced {
        let Some((price, source, built_in)) = self.base(bucket) else {
            return Priced::Unknown;
        };
        let mut nano = price.cost_nano(usage);
        if let Some(model) = built_in {
            if bucket.fast {
                nano *= 2;
            }
            if bucket.us_only && us_surcharge(&model) {
                nano = nano * 11 / 10;
            }
        }
        Priced::Cost(nano, source)
    }
}

/// Whether `name` matches `pattern`, where `*` stands for any characters.
#[must_use]
pub fn matches(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == name;
    }
    let (first, last) = (parts[0], parts[parts.len() - 1]);
    if !name.starts_with(first)
        || !name[first.len()..].ends_with(last)
        || name.len() < first.len() + last.len()
    {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for part in &parts[1..parts.len() - 1] {
        match rest.find(part) {
            Some(at) => rest = &rest[at + part.len()..],
            None => return false,
        }
    }
    true
}

/// A price in dollars per million tokens (`2`, `2.5`, `0.125`) as
/// thousandths of a dollar; at most three decimals.
fn milli(text: &str) -> Option<u64> {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty() && fraction.is_empty()
        || fraction.len() > 3
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let fraction: u64 = format!("{fraction:0<3}").parse().ok()?;
    whole.checked_mul(1000)?.checked_add(fraction)
}

/// Billionths of a dollar as dollars for a person: `$3.12`, `$0.0042`,
/// `$0.00`.
#[must_use]
pub fn dollars(nano: u128) -> String {
    if nano >= 1_000_000_000 || nano == 0 {
        let cents = (nano + 5_000_000) / 10_000_000;
        format!("${}.{:02}", cents / 100, cents % 100)
    } else {
        let ten_thousandths = (nano + 50_000) / 100_000;
        format!("$0.{ten_thousandths:04}")
    }
}

/// Billionths of a dollar as whole millionths, rounded.
#[must_use]
pub fn micro(nano: u128) -> u128 {
    (nano + 500) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usage(input: u64, write: u64, write_1h: u64, read: u64, output: u64) -> Usage {
        Usage {
            input,
            cache_write: write,
            cache_write_1h: write_1h,
            cache_read: read,
            output,
        }
    }

    #[test]
    fn model_names_lose_platform_suffixes_and_dates() {
        assert_eq!(
            normalize("claude-opus-5-5").as_deref(),
            Some("claude-opus-5-5")
        );
        assert_eq!(
            normalize("claude-haiku-4-5-20251001").as_deref(),
            Some("claude-haiku-4-5")
        );
        assert_eq!(
            normalize("us.anthropic.claude-sonnet-4-5-20250929-v1:0").as_deref(),
            Some("claude-sonnet-4-5")
        );
        assert_eq!(
            normalize("claude-opus-4-5@20251101").as_deref(),
            Some("claude-opus-4-5")
        );
        assert_eq!(
            normalize("claude-opus-5-5[1m]").as_deref(),
            Some("claude-opus-5-5")
        );
        assert_eq!(normalize("gpt-5.6-terra"), None);
    }

    #[test]
    fn built_in_prices_cover_cache_tiers_and_modifiers() {
        let prices = Prices::default();
        let opus = Bucket::plain("claude-opus-5-5");
        // 1M of each: $4 + $5 + $8 + $0.20 + $20 = $37.20.
        let all = usage(1_000_000, 1_000_000, 1_000_000, 1_000_000, 1_000_000);
        assert_eq!(
            prices.cost(&opus, &all),
            Priced::Cost(37_200_000_000, "built-in")
        );
        let fast = Bucket {
            fast: true,
            ..opus.clone()
        };
        assert_eq!(
            prices.cost(&fast, &all),
            Priced::Cost(74_400_000_000, "built-in")
        );
        let us = Bucket {
            us_only: true,
            ..opus
        };
        assert_eq!(
            prices.cost(&us, &all),
            Priced::Cost(40_920_000_000, "built-in")
        );
        let old_us = Bucket {
            us_only: true,
            ..Bucket::plain("claude-sonnet-4-5-20250929")
        };
        assert_eq!(
            prices.cost(&old_us, &usage(1_000_000, 0, 0, 0, 0)),
            Priced::Cost(3_000_000_000, "built-in")
        );
        let haiku_long = Bucket {
            long_prompt: true,
            ..Bucket::plain("claude-haiku-5-5")
        };
        assert_eq!(
            prices.cost(&haiku_long, &usage(1_000_000, 0, 0, 0, 1_000_000)),
            Priced::Cost(3_000_000_000, "built-in")
        );
        assert_eq!(
            prices.cost(
                &Bucket::plain("claude-opus-4-0"),
                &usage(1_000_000, 0, 0, 0, 0)
            ),
            Priced::Cost(15_000_000_000, "built-in")
        );
        assert_eq!(
            prices.cost(&Bucket::plain("gpt-5.6-terra"), &all),
            Priced::Unknown
        );
        assert_eq!(
            prices.cost(&Bucket::plain("claude-3-5-sonnet"), &all),
            Priced::Unknown
        );
    }

    #[test]
    fn a_price_file_adds_and_overrides_models() {
        let prices = Prices::parse(
            "# OpenAI\ngpt-5.6-* input=1.25 output=10 cache_read=0.125\nclaude-opus-5-5 input=1 output=2\n",
        )
        .unwrap();
        assert_eq!(
            prices.cost(
                &Bucket::plain("gpt-5.6-terra"),
                &usage(1_000_000, 0, 0, 2_000_000, 100_000)
            ),
            Priced::Cost(2_500_000_000, "price file")
        );
        // A file's price is not doubled for fast mode.
        let fast = Bucket {
            fast: true,
            ..Bucket::plain("claude-opus-5-5")
        };
        assert_eq!(
            prices.cost(&fast, &usage(1_000_000, 1_000_000, 0, 0, 0)),
            Priced::Cost(2_000_000_000, "price file")
        );
        for (text, line) in [
            ("m input=1", 1),
            ("\nm input=1 output=x", 2),
            ("m input=1 output=2 tip=3", 1),
            ("m input=1 output=2 input=3", 1),
            ("m input=0.0001 output=2", 1),
            ("m input", 1),
        ] {
            assert_eq!(Prices::parse(text).unwrap_err().0, line, "{text}");
        }
    }

    #[test]
    fn patterns_and_dollars() {
        assert!(matches("gpt-*", "gpt-5.6-terra"));
        assert!(matches("*terra", "gpt-5.6-terra"));
        assert!(matches("gpt-*-terra", "gpt-5.6-terra"));
        assert!(!matches("gpt-*-luna", "gpt-5.6-terra"));
        assert!(!matches("a*a", "a"));
        assert_eq!(dollars(3_124_000_000), "$3.12");
        assert_eq!(dollars(4_200_000), "$0.0042");
        assert_eq!(dollars(0), "$0.00");
        assert_eq!(micro(1_499), 1);
        assert_eq!(milli("0.125"), Some(125));
        assert_eq!(milli(".5"), Some(500));
        assert_eq!(milli("."), None);
    }
}
