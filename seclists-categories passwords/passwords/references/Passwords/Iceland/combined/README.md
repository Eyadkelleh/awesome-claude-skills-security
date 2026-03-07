# Password Analysis

## Goal

The objective of this analysis is to create targeted, effective wordlists for security testing against Icelandic systems by:

- Identifying the most common password construction patterns used by Icelandic users
- Extracting frequently used words, names, numbers, and special characters from real breach data
- Focusing on common password lengths (4-12 characters)
- Generating usable, trimmed wordlists for (authorized) Icelandic user password brute forcing

## Dataset Overview

- **Total unique passwords analyzed**: 77,752
- **Total password frequency**: 94,666

**Source Data**: This analysis combines and deduplicates data from two primary sources:

- `most-common-passwords.csv` - 57,483 passwords
- `vodafone.csv` - 20,269 passwords
- **Combined total**: 77,752 unique passwords

_Note: All statistics and patterns shown below reflect the combined dataset._

### Name Recognition Methodology

Name identification was compiled from the following sources:

- **[Sarpur.is](https://sarpur.is/Spurningaskra.aspx?ID=531333)** - Collection of nicknames
- **[Íslensk mannanöfn eftir notkun](https://is.wikipedia.org/wiki/%C3%8Dslensk_mannan%C3%B6fn_eftir_notkun)** - Wikipedia list of Icelandic names by usage
- **[Hundanöfn](http://www.steinegg.is/isrima/page8/hundanofn.html)** - 300 Pet names commonly used in Iceland

**Accuracy Disclaimer**: This automated classification may result in some false positives where common words are classified as names, or false negatives where actual names are classified as words. The classification should be considered approximate for analytical purposes.

## Top Password Patterns

### General Patterns (≥1%)

_Note: Uppercase 'W' in patterns indicates capitalized words (e.g., 'Word' = first letter capitalized, 'word' = lowercase)_

| Pattern          | Count  | Percentage |
| ---------------- | ------ | ---------- |
| word+number      | 39,107 | 41.3%      |
| word             | 25,570 | 27.0%      |
| number           | 8,351  | 8.8%       |
| word+number+Word | 4,843  | 5.1%       |
| number+word      | 3,294  | 3.5%       |
| Word+number      | 3,005  | 3.2%       |
| Word             | 1,174  | 1.2%       |

### Detailed Patterns (≥1%)

_Specific subcategories that try to distinguish between different types of numbers, years, and name usage._

| Pattern          | Count          |
| ---------------- | -------------- |
| word             | 19,760 (20.9%) |
| word+number      | 17,182 (18.2%) |
| word+year2       | 9,223 (9.7%)   |
| number           | 8,132 (8.6%)   |
| name             | 5,810 (6.1%)   |
| name+number      | 5,677 (6.0%)   |
| name+year2       | 4,939 (5.2%)   |
| word+number+word | 2,510 (2.7%)   |
| number+word      | 2,184 (2.3%)   |
| word+year4       | 1,285 (1.4%)   |

## Component Analysis

### Top Names (≥0.1%)

| Name   | Count      |
| ------ | ---------- |
| siggi  | 189 (0.2%) |
| anna   | 152 (0.2%) |
| gunnar | 125 (0.1%) |
| sara   | 124 (0.1%) |
| helga  | 118 (0.1%) |
| steini | 113 (0.1%) |
| gummi  | 112 (0.1%) |
| nonni  | 105 (0.1%) |
| birta  | 104 (0.1%) |
| kiddi  | 104 (0.1%) |
| hildur | 101 (0.1%) |
| magga  | 100 (0.1%) |
| kalli  | 95 (0.1%)  |

### Top Words (≥0.1%)

| Word      | Count                                                                                          |
| --------- | ---------------------------------------------------------------------------------------------- |
| fbobh     | 873 (0.9%) - [Noise data](https://www.sciencedirect.com/science/article/pii/S2666281721000949) |
| mamma     | 242 (0.3%)                                                                                     |
| liverpool | 140 (0.1%)                                                                                     |
| hundur    | 127 (0.1%)                                                                                     |
| is        | 124 (0.1%)                                                                                     |
| kassi     | 107 (0.1%)                                                                                     |
| island    | 97 (0.1%)                                                                                      |

### Common Numbers

| Number | Count        |
| ------ | ------------ |
| 1      | 8,220 (8.7%) |
| 123    | 2,578 (2.7%) |
| 2      | 2,313 (2.4%) |
| 3      | 1,678 (1.8%) |
| 4      | 1,552 (1.6%) |
| 6      | 1,399 (1.5%) |
| 7      | 1,351 (1.4%) |
| 5      | 1,226 (1.3%) |
| 8      | 1,062 (1.1%) |
| 9      | 974 (1.0%)   |
| 0      | 929 (1.0%)   |
| 1234   | 597 (0.6%)   |
| 123456 | 383 (0.4%)   |
| 12345  | 230 (0.2%)   |
| 666    | 210 (0.2%)   |

### Common Years

_Note: These are standalone 2-digit patterns that **may** represent years (e.g., birth years like '85 for 1985, or '22 for 2022), but could also be months, days, or arbitrary 2-digit combinations._

| Pattern | Count        |
| ------- | ------------ |
| 12      | 1,471 (1.6%) |
| 11      | 810 (0.9%)   |
| 10      | 773 (0.8%)   |
| 13      | 556 (0.6%)   |
| 22      | 493 (0.5%)   |
| 69      | 435 (0.5%)   |
| 99      | 433 (0.5%)   |
| 88      | 423 (0.4%)   |
| 23      | 417 (0.4%)   |
| 01      | 361 (0.4%)   |
| 77      | 360 (0.4%)   |
| 66      | 347 (0.4%)   |
| 15      | 292 (0.3%)   |
| 21      | 281 (0.3%)   |
| 00      | 268 (0.3%)   |

### Special Characters

| Character | Count        |
| --------- | ------------ |
| .         | 1,132 (1.2%) |
| \_        | 1,054 (1.1%) |
| $         | 336 (0.4%)   |
| !         | 314 (0.3%)   |
| -         | 271 (0.3%)   |
| #         | 158 (0.2%)   |
| &         | 146 (0.2%)   |
| \*        | 139 (0.1%)   |
| "         | 138 (0.1%)   |
| @         | 110 (0.1%)   |
| '         | 105 (0.1%)   |
| )         | 103 (0.1%)   |
| %         | 101 (0.1%)   |
| ?         | 98 (0.1%)    |
| (         | 96 (0.1%)    |

## Password Length Distribution

| Length | Count          |
| ------ | -------------- |
| 8      | 22,881 (24.2%) |
| 6      | 17,399 (18.4%) |
| 7      | 14,142 (14.9%) |
| 9      | 11,665 (12.3%) |
| 10     | 9,685 (10.2%)  |
| 5      | 5,452 (5.8%)   |
| 4      | 4,924 (5.2%)   |
| 11     | 2,486 (2.6%)   |
| 15     | 1,391 (1.5%)   |
| 12     | 1,354 (1.4%)   |

## Results

### Key Statistics

- **Most effective pattern**: word+number (41.3% of passwords)
- **Optimal length range**: 4-12 characters covers 95% of passwords
- **Peak length**: 8 characters (24.2% of all passwords)

### Trimming Strategies

_Patterns generating >100,000 combinations are trimmed using most frequent words to prevent excessive file sizes._

| Pattern          | Components             | Full Combinations | Trim Strategy                                 |
| ---------------- | ---------------------- | ----------------- | --------------------------------------------- |
| word             | 1,921 words            | 1,921             | Use full list                                 |
| name             | 1,019 names            | 1,019             | Use full list                                 |
| number           | 11,509 numbers         | 11,509            | Use full list                                 |
| word+number      | 1,921 × 11,509         | 22,107,229        | **Top 500 words + top 100 numbers = ~50,000** |
| word+year        | 1,921 × 253            | 486,013           | **Top 500 words + top 100 years = ~50,000**   |
| name+number      | 1,019 × 11,509         | 11,729,671        | **Top 500 names + top 100 numbers = ~50,000** |
| name+year        | 1,019 × 253            | 257,807           | **Top 500 names + top 100 years = ~50,000**   |
| number+word      | 11,509 × 1,921         | 22,107,229        | **Top 100 numbers + top 500 words = ~50,000** |
| word+number+word | 1,921 × 11,509 × 1,921 | 42,464,696,749    | **Top 100 words + top 50 numbers = ~75,000**  |

### Final Wordlist

- 472,577 unique passwords from combined, generated wordlists based on most popular words, numbers and patterns
- 2,940 words and 11,510 numbers were used as they appeared 3< times in the combined datasets
- Includes Icelandic words, names, places, etc.
- Focused on 4-12 character range (95% coverage)

### Temporal Limitations

This analysis is based on historical breach data that may be several years old. User password behavior and security awareness is constantly evolving (and enforced).
